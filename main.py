import functools


# Extract the source and destination ip from the tcp address txt files
def get_src_dest(name):
    try:
        with open(name) as fp:
            return fp.read().split()
    except:
        return "err", "err"


# Extract the binary from a dat file
def read_dat_file(name):
    try:
        with open(name, "rb") as fp:
            return fp.read()
    except:
        return None


# Takes a string representing an ip and returns array containing sequence of bytes
def from_ip_to_four_bytes(ip):
    nums = [int(x).to_bytes(byteorder='big', length=1) for x in ip.split('.')]
    return functools.reduce(lambda a, b: a + b, nums)


# Confirm that ip correctly transforms
def test_ip_to_four_bytes():
    ip = '1.2.3.4'
    expected = b'\x01\x02\x03\x04'
    assert from_ip_to_four_bytes(ip) == expected


# Gets the length of the TCP data
def get_tcp_data_length(dat_contents):
    return len(dat_contents)


# Generate the ip pseudo header in byte fromat
def generate_ip_pseudo_header_bytes(src_ip_bytes, dst_ip_bytes, len_dat_payload):
    zero = b'\x00'
    ptcl = b'\x06'
    ip_pseudo_header = src_ip_bytes + dst_ip_bytes
    ip_pseudo_header = ip_pseudo_header + zero + ptcl
    ip_pseudo_header = ip_pseudo_header + len_dat_payload.to_bytes(byteorder='big', length=2)
    return ip_pseudo_header


# Extract checksum from the dat file
def extract_checksum(dat_contents):
    return int.from_bytes(dat_contents[16:18], byteorder='big')


# Generate the zero checksum using the dat contents
def generate_zero_checksum(dat_contents):
    tcp_zero_cksum = dat_contents[:16] + b'\x00\x00' + dat_contents[18:]
    if len(tcp_zero_cksum) % 2 == 1:
        tcp_zero_cksum += b'\x00'
    return tcp_zero_cksum


# Calculate the checksum using the zero checksum
def checksum(pseudoheader, tcp_data):
    data = pseudoheader + tcp_data
    offset = 0
    total = 0
    while offset < len(data):
        word = int.from_bytes(data[offset:offset + 2], "big")
        total += word
        total = (total & 0xffff) + (total >> 16)
        offset += 2
    return (~total) & 0xffff


# test_ip_to_four_bytes()

for i in range(10):
    tcp_addr_file = 'tcp_addrs_{}.txt'.format(i)
    tcp_data_file = 'tcp_data_{}.dat'.format(i)

    src, dest = get_src_dest(tcp_addr_file)
    tcp_data = read_dat_file(tcp_data_file)

    dat_checksum = extract_checksum(tcp_data)
    dat_length = get_tcp_data_length(tcp_data)

    src_ip_bytes = from_ip_to_four_bytes(src)
    dest_ip_bytes = from_ip_to_four_bytes(dest)

    pseudo_header = generate_ip_pseudo_header_bytes(src_ip_bytes, dest_ip_bytes, dat_length)

    zero_checksum = generate_zero_checksum(tcp_data)
    calculated_checksum = checksum(pseudo_header, zero_checksum)

    # print('Checksum within data:', hex(dat_checksum))
    # print('Calculated checksum: ', hex(calculated_checksum))

    if calculated_checksum == dat_checksum:
        print('PASS')
    else:
        print('FAIL')




