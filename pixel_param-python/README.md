This folder contains prototype python code that generates public parameters for pixel.
It also contains a known answer test (KAT) file that can be use to
cross check the default parameter from Rust implementation.

Make sure to set the path in `param.py` before running the tests.
To run the cross checks:
* `python param.py`: this will generate a parameter set with a default `seed = SHA512_IV`, using
python codes. The parameters are serialized (uncompressed) and stored in `kat_python.txt`. It
should match the `kat.txt` that is provided.
