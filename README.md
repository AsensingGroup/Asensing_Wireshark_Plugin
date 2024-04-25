# Asensing Wireshark Plugin

Asensing protocol (IMU, LiDAR) lua interpreter plugin for Wireshark.



## Usage

Find the lua plugin you need in the `source` directory, and copy it to the Wireshark installation directory.

Of course you can also copy all the plugins, like this:

```bash
$ sudo cp source/*.lua /usr/share/wireshark/
```

Modify the `init.lua` file in the Wireshark installation directory, add the following content at the end:

```bash
dofile(DATA_DIR.."xxx.lua")
```

Save the `init.lua` file.

Now, open the Wireshark tool, or press `Ctrl + Shift + L` to reload the plugin.



## Reference

- [Lua - Wireshark Wiki](https://wiki.wireshark.org/Lua)
