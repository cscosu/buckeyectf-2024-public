from Crypto.Cipher import AES

my_message = "\n".join(
    [
        "Grate the raw potatoes with a cheese grater, place them into a bowl and cover completely with water. Let sit for 10 minutes.",
        "Drain the grated potatoes well; if this is not done thoroughly the potatoes will steam instead of fry.",
        "Mix in chopped onions by hand.",
        "Mix the egg OR flour into the hash brown mixture evenly. This will allow the hash browns to stay together when frying.",
        "Place a large frying pan on medium-high heat and add enough oil to provide a thin coating over the entire bottom of the pan.",
        "When the oil has come up to temperature apply a large handful of potatoes to the pan and reshape into a patty that is about 1/4-1/2 inch (6-12 mm) thick. The thinner the patty, the crispier the hash browns will be throughout.",
        "Flip when they are crisp and brown on the cooking side. They should also stick together nicely before they are flipped. This should take about 5-8 minutes.",
        "The hash browns are done when the new side is brown and crispy. This should take another 3-5 minutes.",
    ]
).encode()


def aes(block: bytes, key: bytes) -> bytes:
    assert len(block) == len(key) == 16
    return AES.new(key, AES.MODE_ECB).encrypt(block)


def hash(data: bytes):
    data = pad(data, 16)
    state = bytes.fromhex("f7c51cbd3ca7fe29277ff750e762eb19")

    for i in range(0, len(data), 16):
        block = data[i : i + 16]
        state = aes(block, state)

    return state


def sign(message, secret):
    return hash(message + secret)


def pad(data):
    padding_length = 16 - len(data) % 16
    return data + b"_" * padding_length


state = bytes.fromhex(input("Their signiature?\n> "))
new_hash = aes(pad(b"french fry"), state)

print((pad(my_message) + b"french fry").hex())
print(new_hash.hex())