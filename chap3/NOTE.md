# JSON-encoded string

JSON中的字符格式第一次看很让我困扰, `\n`转义字符表示newline可以理解，
但在JSON中为`\\n`, 为啥平白多出一个`\`?

JSON中的字符是没有打印含义的纯字符，所以在保持一个`\n`时其需要保存两个字符
`\`和`n`, 而不是作为一个单一的转义后的转义字符. 而在C字符串中，`\`本身需要
转义，所以`\\n`表示的是两个字符.

同样对于`\\`也是如此，对于打印含义来说`\\`转义为'\', 但JSON需要保存纯字符串，
所以两个`\\`都要分别被转义，最后变成`\\\\`了.

# TDD
首先要确保test.c编写正确=。=. 这要求你首先对需求功能有清晰的了解. 

# stack buffer

string的长度不是固定的 -- 其内存空间是不确定的. 所以需要一个动态的内存空间作为
缓存，暂时存储解析出的字符串. 这里实现的过程很简单:
* `push`: realloc()额外分配一段内存，返回无内容的第一个位置的地址，
该地址段可以暂时存放新的内存.
* pop: 减少top指针(实际是integer的第一个可用字节的偏移量), 存储的一段内存
复制给新分配的string内存. 

有了动态内存，就要时刻注意free()已经分配且之后不需要的内存块. 这里每次
设置新的值之前以及测试的最后都需要调用`lept_free()`.


