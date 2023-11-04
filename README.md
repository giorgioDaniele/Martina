# Martina

Martina is a network service that allows you to create a TCP tunnel through which traffic destined for a local network can travel. Basically, with Martina you can create a tunnel to access a remote network as if your machine were physically inside that network. 

## Building

Please make sure you have installed OpenSSL library. If so, just run the Makefile.

```bash
make all
```

## Usage

On server-side
```c
./server_prog <private_network_id> <private_network_mask> <remote_network_id> <remote_network_mask> 
```

On client-side
```c
./client_prog
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.
