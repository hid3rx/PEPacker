# 介绍

PEPacker是一款PE加壳工具。本工具目前仅支持对64位程序加壳。

# 特点

+ PE格式良好的兼容性（感谢AtomPePacker项目）；
+ 使用密码保护，在缺失密码的情况下，被加壳程序无法运行，也无法提取分析；
+ 使用Base64编码降低加壳段的熵值，降低查杀概率；
+ 加壳段体积往往较大，所有主动增大 `.text` 段体积避免段间体积比例失衡。

# 编译

开发环境为Visual Studio 2019，项目依赖 `crypto++` 库，推荐使用 `vcpkg` 安装：

```
.\vcpkg install cryptopp:x64-windows
.\vcpkg install cryptopp:x64-windows-static
.\vcpkg install cryptopp:x64-windows-static-md
```

安装完依赖后直接编译即可。

# 使用方式

**编译程序：**编译完成会获得 `PEPacker.exe` 和 `PEStub.exe` 两个文件，其中 `PEPacker.exe` 是加壳工具，`PEStub.exe` 是存根文件，确保这两个文件同时放置在同一目录下。由于加壳程序使用了加密技术，加密与解密都需要用到密钥文件。

**准备密钥文件：**加壳前需要准备密钥文件，PEPacker使用了AES加密算法保护被加壳文件，在同级目录下新建一个 `LICENSE.txt` 文件，其中写入HEX格式的AES密钥，长度支持128/192/256位，为了方便，密钥可以使用MD5或SHA256算法生成，例如：`e10adc3949ba59abbe56e057f20f883e` 。

**使用以下指令加壳：**

```` 
PEPacker.exe [Path to PE File]
````

加壳完毕后会生成 `Packed.exe` 文件，即为加壳后的程序。

**使用方式：**由于有密码的保护，加壳程序执行时需要确保 `LICENSE.txt` 文件放在同级目录，后续的使用与原被加壳程序无区别。

# 感谢

https://github.com/NUL0x4C/AtomPePacker

https://github.com/weidai11/cryptopp

