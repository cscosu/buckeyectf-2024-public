# kebr2

## Check Solve

```console
python3 solve.py
```

## Intended Solve

Users open the pcap to find another keyboard recording but this time it doesn't look like typing of anything interesting. They will see usbhid messages starting with `0xA9` that aren't specified anywhere.

The user can search for the device by grabbing the vendorId and productId from the first couple packets. They can use this to find that the device is a Keychron Q1 HE keyboard.

**Note**: The only way I have found to find the vendor id is to search for this exact string on GitHub `"pid": "0x0B10",` which will find a forked repo of the official one.

The keyboard can be configured using a web ui at https://launcher.keychron.com/ using usbhid communication. To solve, they must disect the firmware source code to parse the hid packets.

After parsing, it looks like the the actuation point on the keys was set one by one. Finding these keys reveals the flag.
