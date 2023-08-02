# run.codes Compiler - Monitor

This program monitors the execution of another program. In particular, it
gathers information such as the running time, exit status and/or signal that
ended its execution.

**Disclaimer:** this solution, even though it works, might not be sufficient on preventing
miss-use from the users, might be a good idea to take a look of evolving this project and
including other solutions like firejail.

## Usage

```sh
monitor [options]
```

### Options

| Option | Description                                                          |
| ------ | -------------------------------------------------------------------- |
| `-f`   | Maximum file size (bytes) that the program can create                |
| `-m`   | Maximum memory size (bytes) the program can allocate                 |
| `-i`   | File path to where the monitored program will read from              |
| `-o`   | File path to where the monitored program will output to              |
| `-e`   | File path to where the monitored program will output errors to       |
| `-c`   | Command to be executed (single string with the command and its args) |

### Example

```sh
monitor -i input.txt -o output.txt -e error.txt 'program arg1 arg2'
```

## License

For information on the license of this project, please see our [license file](LICENSE.md).

## Contributors

For information of the contributors of this project, please see our [contributors file](CONTRIBUTORS.md).

## Contributing

For information on contributing to this project, please see our [contribution guidelines](CONTRIBUTING.md).
