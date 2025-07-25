# Scar4Sud OMNeT++ Simulation

This is an OMNeT++ project that simulates secure communication between components in a car network.

## Setup

This projects need the following dependencies:

- OpenSSL (version >= 1.0)
- SoftHSMv2
- pkcs11-tool (for `util.sh` config utility)

> [!NOTE]
>
> On Debian based environments install also the `dev` version of this libraries.
>
> Building SoftHSMv2 from source gives more reliable results in terms of assuring its functionality.

To compile the simulation run in `Progetto/src`:

```bash
$ opp_makemake -f --deep -lssl -lcrypto -lsofthsm2
$ make clean
$ make
```

To initialize the SoftHSMv2 library for use with this project execute the `util.sh` script in the `util/hsm_key_setup` directory. It will create a new SoftHSMv2 token called `car-token` and it will populate it with the ECU public keys and HSM private key that are found in  `hsm_key_setup`. 
The scripts assumes that the `libsofthsm2.so` library file is found at `/usr/lib/softhsm`. It also depends on `pkcs11-tool` for entering the keys into SoftHSMv2.



If SoftHSMv2 has been installed with its default setting the objects stored by SoftHSM will be found at `/var/lib/softhsm/tokens`. 

## Directory Structure

### `simulations`

Contains the running environment of the simulation:

- `.ned` and `.ini` configuration files defining parameters of the simulations, of its nodes and of their connections.
- `storage` a directory that contains folders representing the local storage of each ECU.
- `tpm_storage` a directory that contains folders representing the contents of each ECU TPM.

### `src`

Contains the simulation source files:

-  The NED language defined network modules and their c++ class implementations. 
- Collection of c++ functions for simulating ECU and TPM crypto behavior via openssl functions.
- Collection of c++ classes, and function for simulating HSM behavior via SoftHSM PKCS#11 simulated interface.

### `util`

Contains the key that are to be used by the HSM and a script `util.sh` for inserting them in a SoftHSM token.
