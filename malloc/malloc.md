## glibc2.20 malloc源码分析

### 1. _int_malloc

_int_malloc中首先将请求的size转换成内部真实的堆块大小，其实就是请求大小加上堆块头部大小，当然还要保证大小大于能分配的堆块大小的最小值。

![image-20210218210745277](https://i.loli.net/2021/02/18/H5aABLp3IdUYXqx.png)

##### 1.1 fastbin

判断是否能够从fastbin中找到合适的空闲堆块来进行分配，fastbin是一个单链表数组。

- 要求大小不能超过fastbin的最大值，64位最大值为0x80，32位最大值为0x40。

- 根据堆块大小得到fastbin中的下标，64位步长为0x10，32位步长为8。

- 从对应下标的fastbin中取出堆块victim，并更新fastbin[index]指向的堆块为victim->fd。
- 检查victim的size字段，看是否与所需的堆块大小相符。
- 对victim进行一些合法性的检查，如堆块size是否对齐，size是否大于需要的size，堆块size与需要的size相差值是否小于步长。
- 返回的堆块地址为真实堆块地址加上堆块头的大小。

![image-20210218220620995](https://i.loli.net/2021/02/18/IFWPYsuH5nRk6Uc.png)

##### 1.2 small bin

在fastbin中没找到合适的堆块，就会到small bin中寻找。small bin是一个循环双链表数组。

- 先检查需求堆块大小是否在small bin的范围内。
- 根据堆块大小得到堆块所在链表在small bin中的下标。
- 取链表头指向的上一块堆块，若其不等于0或链表头，则其为victim。
- 对victim进行双链表检查，判断victim->bk->fd是否等于victim，通过检查就可以将victim从链表中解下。
- 收尾的操作与fastbin相同。

![image-20210218221725528](https://i.loli.net/2021/02/18/bjAHf1nYu86FWKi.png)

##### 1.3 unsorted bin

在查找unsorted bin之前，若堆块大小超出small bin的范围，则会先对fastbin中的堆块进行consolidate来处理内存碎片问题。

![image-20210219102709190](https://i.loli.net/2021/02/19/8AISevJcPBpOilj.png)

接下来取unsorted bin链表头指向的前一块堆块，若需求的堆块size在small bin范围内就会尝试直接从last remainder上割一块下来分配。由于unsorted bin是采用best fit算法的，所以每次分配都需要遍历一遍链表，在这个过程中会根据空闲堆块的大小将它们放入small bin或large bin中，这样最后就只会在unsorted bin中留下一块堆块，这就是last remainder了。程序会优先用这块堆块分配，虽然是不符合best fit算法的但是可以提高效率。

![image-20210219104349945](https://i.loli.net/2021/02/19/vNTwXDtAc5yo8mg.png)

若无法从last remainder中分配，那就只有遍历unsorted bin寻找最适合的空闲堆块了，即victim的大小正好与需要的大小相等。先将victim从unsorted bin上解下，可以注意到这个版本的malloc中unsorted bin解链时是没有双链表检测的，所以存在unsorted bin attack的可能。

![image-20210219120432844](https://i.loli.net/2021/02/19/lVLi4AvezO69IaN.png)

![image-20210219104536952](https://i.loli.net/2021/02/19/ipdNLsWTOc8ImQz.png)

每次遇到不适合的victim就会如上文所述，将其放入small bin或是large bin中。

- small bin

找到对应链表在small bin中的下标，拿到链表头指向的前一块堆块以及链表头，为了之后插入victim做准备。

![image-20210219105632917](https://i.loli.net/2021/02/19/PrpQLxsRCgFVoOf.png)

- large bin

large bin要复杂一些，因为多了2个字段fd_nextsize和bk_nextsize，这是因为large bin每个bin存储的堆块大小不再是一个确定值而是一个范围，fd和bk将同一大小堆块组织成一条链表，可以将它看作是一条纵向的链表，fd_nextsize和bk_nextsize在不同大小的堆块间构成一条链表，而且是按大小降序排序的，将其看作一条水平的链表。

先检查这个bin是否为空，若是则直接将victim插入，fd_nextsize和bk_nextsize都指向它自己。

![image-20210219113048288](https://i.loli.net/2021/02/19/hyfHgwP4imcJuNr.png)

![image-20210219113106935](https://i.loli.net/2021/02/19/7QtHO254CXMyoRL.png)

若不为空则考虑不同大小的情况，若victim大小小于bin中指向的最小堆块大小，则直接插入水平链表。

![image-20210219113723117](https://i.loli.net/2021/02/19/STk1MbCfIjOc3wP.png)



若比最小堆块大则从最大堆块开始，沿着水平链表寻找刚好不大于victim的堆块。

![image-20210219115300471](https://i.loli.net/2021/02/19/RCk1vJQBcPm724K.png)

若找到的这块堆块刚好与victim大小相等，则将victim按纵向插入到它之后，这是为了避免更改水平链表中相邻节点的fd_nextsize和bk_nextsize指针。

![image-20210219115427536](https://i.loli.net/2021/02/19/J16hgPwnq5ElANX.png)

若是更大，就插入到水平链表中。

![image-20210219115544335](https://i.loli.net/2021/02/19/IyAEjnpQr4soH1i.png)

以下是最后的插入纵向链表的操作。

![image-20210219120033684](https://i.loli.net/2021/02/19/DLuXeB2ZaTm5RM9.png)

##### 1.4 最符合的large bin

如果继续向下执行，说明在unsorted bin中没有找到与需求堆块相同大小的空闲堆块。此时已经把unsorted bin中的堆块放入到了small bin和large bin中，所以要分配堆块的话还要从这两种bin里来找。这一步考虑的是需求堆块大小大于small bin的情况。

- 首先检查large bin是否为空，或是最大的堆块都小于需求堆块大小。

![image-20210219150937817](https://i.loli.net/2021/02/19/SWT37eRhVNjZJv6.png)

- 在large bin中沿着水平链表找到最小的比需求大小大的纵向链表，将其第二个节点作为victim(还是为了避免更改水平链表相邻节点的fd_nextsize和bk_nextsize指针)。

![image-20210219151207963](https://i.loli.net/2021/02/19/oczdFiR4VJE3lLf.png)

- 判断被切割后剩余的堆块尺寸是否足够大，若太小则不切割一并分配。

![image-20210219151427289](https://i.loli.net/2021/02/19/fD29lqwzB3mO6VC.png)

- 切割victim，双链表检测通过后将剩余部分插入到unsorted bin中，完成分配。

![image-20210219151535474](https://i.loli.net/2021/02/19/hyev4Y6wgTjEIW1.png)

##### 1.5 其他large bin

当对应大小范围的large bin无法完成分配时，就用存有更大堆块的large bin来完成分配。具体实现是通过一个for循环来查找。会跳过不含有空闲堆块的bin，系统用binmap这个数组来标识一个bin中是否包含空闲堆块。当可能的large bin都无法完成分配时就会跳转到使用top chunk分配的部分。

![image-20210219153039557](https://i.loli.net/2021/02/19/DlLhVjdZHvaT3fs.png)

但binmap记录的不一定准确，系统还是会检查该large bin是否为空链表。

![image-20210219153424932](https://i.loli.net/2021/02/19/QsgXFrRMwCH5OJS.png)

找到一个可行的large bin后，直接用它存有的最大的堆块来进行分配。之后的切割操作与上一步相同。

##### 1.6 top chunk

large bin无法完成分配就需要从top chunk中切一块下来分配出去了。这是可行性最高的手段，只会受到系统内存大小的限制。

![image-20210219154247203](https://i.loli.net/2021/02/19/5QeGkDuOdzWphJS.png)

在需求堆块尺寸大于top chunk时，会进行fastbin的consolidate，然后继续尝试用small bin和large bin完成分配。

![image-20210219154654126](https://i.loli.net/2021/02/19/vKgfJp5bcue3j8V.png)

若fastbin中也没有空闲堆块，说明合并了内存碎片也无法完成分配，必须要请求系统分配更多的内存空间了。

![image-20210219154806306](https://i.loli.net/2021/02/19/MNzFVyocWYdpRU1.png)

### 2. sysmalloc

上一部分中我们知道了当top chunk不够大，而且内存碎片也都充分利用时仍然无法完成分配就会调用sysmalloc来向系统请求分配更多的内存空间。

##### 2.1 mmap

当请求的内存大小超过mmap要求的最小内存时，并且mmap分配的内存块数目没有超出最大值，就会直接调用mmap分配出一块新的内存块。

![image-20210219161104633](https://i.loli.net/2021/02/19/CBsX6E3MdrKGoi7.png)

将内存大小按页对齐。

![image-20210219161237676](https://i.loli.net/2021/02/19/mDe7owE6Ghzrikx.png)

mmap分配成功后会检查要返回的堆块地址是否是堆块对齐的。若不对齐就会纠正过来。

![image-20210219162924822](https://i.loli.net/2021/02/19/26dFGNy7pAehZrs.png)

最后会调用do_check_chunk函数检查一下分配的堆块地址、大小是否合法，具体就是是否大于最小堆块尺寸，是否对齐，是否超出main heap等。

##### 2.2 非main arena

先用old_top、old_size、old_end分别存储了原来的top chunk及其大小和末尾地址。

若av不是main arena时，先尝试调用grow_heap对top chunk的size进行扩展，并更新av->system_mem和arena_mem。

![image-20210219165740591](https://i.loli.net/2021/02/19/zV9tcZJNfbQwiu2.png)

若扩展失败则调用new_heap分配一块新的堆块，实际上还是调用mmap进行分配。并且会使用新分配的堆块作为新的top chunk，而旧的那块会被free到对应的bin中去。

![image-20210219170149470](https://i.loli.net/2021/02/19/goewE69A4mbsPyS.png)

如果以上两种方式都失败了还是会跳转回开头尝试使用mmap分配内存。

##### 2.3 是main_arena

这部分代码无法理解，先跳过。

### 3. _int_free

函数最开始进行了一些基础的检查，如检查堆块地址是否过大以及是否对齐，检查size是否大于最小值，是否对齐。

![image-20210219214625988](https://i.loli.net/2021/02/19/xuZT7hJvtVeFkKf.png)

##### 3.1 fastbin

进行如下检查，来判断是否插入到fastbin中。

- size处于fastbin范围内且堆块不与top chunk相邻。

  ![image-20210219214714374](https://i.loli.net/2021/02/19/qjcnap9Nzdwxl2X.png)

- 相邻的下一块堆块size是否大于堆块头大小，小于已分配的内存大小。

  ![image-20210219214731919](https://i.loli.net/2021/02/19/UmOuv2AVrGtgY3y.png)

- 对应大小的fastbin链表头指向的堆块与释放的堆块不同。

  ![image-20210219214854099](https://i.loli.net/2021/02/19/h3ZOvaIE51xRolC.png)

- 检查fastbin链表头指向的堆块size是否与释放的堆块的size相同。

  ![image-20210219214923992](https://i.loli.net/2021/02/19/EB2YVIbqxPSaKc8.png)

##### 3.2 unsorted bin

先进行如下检查。

- 释放的堆块是否是top chunk。

  ![image-20210219215047199](https://i.loli.net/2021/02/19/zr2d7eFIhOBgTuj.png)

- 释放堆块相邻的下一块堆块是否超出了arena的边界。

  ![image-20210219215123411](https://i.loli.net/2021/02/19/SNgPOxCFbT67Lyh.png)

- 相邻的下一块堆块的prev_inuse位是否为1。

  ![image-20210219215225161](https://i.loli.net/2021/02/19/KRkWL5FrdGEqv7S.png)

- 相邻的下一块堆块size是否大于堆块头大小，小于已分配的内存大小。

  ![image-20210219215249643](https://i.loli.net/2021/02/19/JkWdG5Zn3OIiAmY.png)

然后考虑合并相邻堆块的可能。

- 若被释放堆块的prev_inuse位为0，则进行后向合并，将相邻的前一块堆块从双链表中解下，将它们的size相加，更新释放堆块的地址为前一块堆块的地址。

  ![image-20210219214417270](https://i.loli.net/2021/02/19/AawEvySlgtRHoMh.png)

- 若相邻的下一块堆块的再下一块堆块的prev_inuse位为0，则进行前向合并，将后一块堆块从双链表中解下，并将size相加。否则的话就将相邻的下一块堆块的prev_inuse位置为0。

  ![image-20210219214502061](https://i.loli.net/2021/02/19/x7jwVau2MmhbSKF.png)

将释放的堆块插入到unsorted bin中，不过在此之前需要检查unsorted bin的双链表完整性。

![image-20210219214341619](https://i.loli.net/2021/02/19/LAhCbftQKc6pwJS.png)

检测通过后插入unsorted bin。

![image-20210219215347891](https://i.loli.net/2021/02/19/fNTjhspCZ23kQiI.png)

##### 3.3 与top chunk相邻

与top chunk相邻的话就直接与top chunk合并，释放的堆块地址变为新的top chunk。

![image-20210219215611019](https://i.loli.net/2021/02/19/soyQErzIAH84Lba.png)

##### 3.4 trim

如果释放的堆块过大，如大于2的20次方，就会引发fastbin的consolidate以及trim操作。

若是main arena且top chunk的大小大于trim所需的阈值，则调用systrim来将brk指针向低地址移动，实际上就是调用morecore系统调用，只是参数为负数，其大小由当前top chunk size与pad的差值有关，而且是页对齐的。

若不是main arena则不可能有brk指针，可以尝试释放通过new_heap分配得到的堆块。

##### 3.5 munmap

若释放的堆块是通过mmap分配的则使用munmap来释放。