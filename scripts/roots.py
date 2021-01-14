import sys

path = sys.argv[1]
contents = open(path, 'r').read()
lines = contents.splitlines()
first_epoch = lines[0].split(':')[0]

# a poor man code generator :D
print(f'pub const DAG_START_EPOCH: u64 = {first_epoch};')
print("lazy_static::lazy_static! {")
print("    pub static ref ROOT_HASHES: Vec<H128> = vec![")
for line in lines:
    parts = line.split(':')
    h = parts[1]
    print(f'        "{h}",')
print("    ]")
print("    .into_iter()")
print("    .map(|v| &v[2..])")
print("    .map(hex::decode)")
print("    .flatten()")
print("    .map(|b| H128::from_slice(&b))")
print("    .collect();")
print("}")
