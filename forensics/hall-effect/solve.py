from dataclasses import dataclass
import itertools
import math
import pyshark

def read_pcapng_file(filename):
    try:
        capture = pyshark.FileCapture(filename)
        return capture
    except FileNotFoundError:
        print(f"The file {filename} was not found.")
        exit(1)

wacko = [
    [],
    ["`", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "-", "="],
    ["<TAB>", "q", "w", "e", "r", "t", "y", "u", "i", "o", "p", "[", "]", "\\"],
    ["<CAPS>", "a", "s", "d", "f", "g", "h", "j", "k", "l", ";", "'", "<ENTER>"],
    ["<SHIFT>", "<DUD>", "z", "x", "c", "v", "b", "n", "m", ",", ".", "/", "<SHIFT>"],
    ["<CTR:>", "<FN>", "<WIN>", "<ALT>", "<SPACE>", "<ALT>", "<CTRL>", "<LEFT>"]
]

def check_device_info(capture):
    device_info = {}
    for packet in capture:
        if 'USB' in packet:
            data_layer = packet.data

            try:
                # Extract product ID and vendor ID
                product_id = data_layer.usb_idproduct
                vendor_id = data_layer.usb_idvendor
                device_info['Product ID'] = product_id
                device_info['Vendor ID'] = vendor_id
                break  # Device info found; exit the loop
            except AttributeError:
                continue

    print("Device Information:")
    for key, value in device_info.items():
        print(f"{key}: {value}")

    assert device_info['Vendor ID'] == "0x3434"
    assert device_info['Product ID'] == "0x0b10"

def parse_usbhid_packets(capture):
    """
    Parses USB HID packets and processes the data.

    capture[14].data.usbhid_data

    Args:
        capture (pyshark.FileCapture): The capture object containing the packets.
    """
    set_travels = []
    for packet in capture:
        if 'USB' in packet:
            try:
                data = packet.data.usbhid_data
                # Convert hex string to bytes
                data_bytes = bytes.fromhex(data.replace(':', ''))
                parsed = parse(data_bytes)
                if parsed:
                    set_travels.append(parsed)

            except AttributeError:
                continue

    for parsed in set_travels[::2]:
        if len(parsed.row_col) < 10:
            print("<" + "".join(parsed.letter()) + ">")


@dataclass
class SetTravel:
    profile: int
    mode: int
    act_pt: int
    sens: int
    rls_sens: int
    entire: bool
    row_mask: list[list[bool]]
    row_col: list[tuple[int, int]]

    def letter(self) -> list[str]:
        return [wacko[row][col] for row, col in self.row_col]

def travel_from_bytes(b: bytes) -> SetTravel | None:
    # ANALOG_MATRIX
    if b[0] != 0xa9:
        return None
    # AMC_SET_TRAVAL
    if b[1] != 20:
        return None

    row_mask = [[0] * 24] * 6
    row_col = []
    row_mask_bytes = b[8:(8 + (6*3))]
    for idx, row_byte in enumerate(row_mask_bytes):
        row = math.floor(idx / 3)
        num_bits = 8
        bits = [(row_byte >> bit) & 1 for bit in range(num_bits - 1, -1, -1)]
        # print(bits)
        row_byte_idx = idx % 3
        for bit_idx, bit in enumerate(bits[::-1]):
            col = bit_idx + (8 * row_byte_idx)
            if bit:
            # if True:
                # print(f"({row}, {col}) -> {bit}")
                row_col.append((row, col))


            row_mask[row][col] = bit == 1


    packet = SetTravel(profile=b[2], mode=b[3], act_pt=b[4], sens=b[5], rls_sens=b[6], entire=b[7] != 0, row_mask=row_mask, row_col=row_col)
    return packet





def parse(b: bytes) -> SetTravel | None:
    parsed = travel_from_bytes(b)
    

    return parsed



def main():
    """
    Main function to execute the script.
    """
    filename = 'capture.pcapng'
    capture = read_pcapng_file(filename)
    print(capture[1].usb)
    check_device_info(capture)

    parse_usbhid_packets(capture)
    # Close the capture to release resources
    capture.close()

if __name__ == "__main__":
    main()
