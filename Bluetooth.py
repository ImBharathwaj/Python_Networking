import bluetooth as bt

nearby = bt.discover_devices(lookup_names=True)
print(len(nearby))
for addr, name in nearby:
    print('Name : {}\t\t->\tAddress : {}'.format(name, addr))
