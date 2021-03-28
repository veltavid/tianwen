## codeql securitylab学习

### 1.ChakraCore-bad-overflow-check

- 查询语句

  ```
  import cpp
  
  predicate check_overflow(LocalScopeVariable var,AddExpr add,RelationalOperation compare)
  {
      compare.getAnOperand()=var.getAnAccess() and
      compare.getAnOperand()=add and
      add.getAnOperand()=var.getAnAccess()
  }
  
  from LocalScopeVariable var,AddExpr add
  where check_overflow(var,add,_) and var.getType().getSize()<4 and
  not add.getConversion+().getType().getSize()<4
  select add," overflow checked on variable type "+var.getUnderlyingType()
  ```

- 漏洞成因

  没考虑到两个优先级小于整型的数在相加时会提升到整型，这叫做整型提升，之后进行比较时就是以int类型进行比较了，即使原本发生了溢出也无法检测出来。

- codeql查询分析
  - 首先是check_overflow谓语，它进行了三重限制，第一是要求比较运算符的一边为一个局部变量var，第二是要求比较运算符另一边为一个加法表达式，第三则要求加法表达式的一边也为var。即过滤出形如var > var + any的语句，这是程序中检查溢出的操作。
  - 第二步在查询语句中添加了var.getType().getSize()<4的限制，这是因为只有优先级小于整型的数在比较时才会发生整型提升导致溢出检测失效。
  - 第三步添加了新的限制not add.getConversion+().getType().getSize()<4，其含义为获取加法表达式整体一次或多次强制类型转换的类型，要求强制转换之后的类型优先级仍然不能超过整型。不过不知道为何改为add.getConversion+().getType().getSize()>=4得到的结果就是错误的。

### 2.Qualcomm-MSM-copy_from_user

- 查询语句

  ```
  import cpp
  import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
  import semmle.code.cpp.dataflow.DataFlow
  import DataFlow::PathGraph
  
  class Config extends DataFlow::Configuration
  {
      Config()
      {
          this="copy_from_user"
      }
  
      override predicate isSource(DataFlow::Node source)
      {
          exists(LocalScopeVariable var | source.asExpr().(AddressOfExpr).getAnOperand()=var.getAnAccess())
      }
  
      override predicate isSink(DataFlow::Node sink)
      {
          exists(Expr dest_arg,Expr size_arg,FunctionCall call |
          call.getTarget().getName()="copy_from_user" and
          dest_arg=sink.asExpr() and
          dest_arg=call.getArgument(0) and
          size_arg=call.getArgument(2) and
          not dest_arg.getType().(PointerType).getBaseType().getSize()>=upperBound(size_arg) and
          not dest_arg.getType().(ArrayType).getSize()>=upperBound(size_arg)
          )
      }
  }
  
  from Config cfg,DataFlow::PathNode source,DataFlow::PathNode sink
  where cfg.hasFlowPath(source,sink)
  select source,sink
  
  ```

- 漏洞成因

  检查copy_from_user的size参数大于dest参数的容量时导致的栈溢出，看起来将copy_from_user换成其他类似的拷贝函数也是没有问题的。

- codeql查询分析
  - 第一步查询出所有调用了copy_from_user的语句。
  - 第二步新增了显示的查询结果，将dest_arg，size_arg，size_arg可能的最小值与最大值和语句所在的文件路径输出。
  - 第三步过滤掉了形如copy_from_user(&s,user_data,sizeof(s))的语句，通过限制dest_arg对应指针类型的容量不大于等于size_arg的最大值实现。
  - 第四步过滤掉了形如copy_from_user(s,user_data,sizeof(s))的语句，通过限制dest_arg对应数组类型的容量不大于等于size_arg的最大值实现。
  - 第五和第六步合起来过滤掉了形如prt=malloc(size)后copy_from_user(ptr,user_data,size)的情况，通过跟踪数据流来判断malloc出的堆块是否就是copy_from_user的dest_arg。
  - 第七步将之前的限制合并到了一个类中，并且新增了要求dest_arg为局部变量的限制，也就是检测将用户数据拷贝到栈上导致的栈溢出。此时已经不需要再进行malloc相关的过滤了。

### 3.XNU_DTrace_CVE-2017-13782

- codeql查询语句

  ```
  import cpp
  import semmle.code.cpp.dataflow.DataFlow
  import DataFlow::PathGraph
  
  class Register_access extends ArrayExpr
  {
      Register_access()
      {
          exists(Function target,LocalScopeVariable var|
              var.getName()="regs" and
              target.getName()="dtrace_dif_emulate" and
              var.getFunction()=target and
              this.getArrayBase() = var.getAnAccess())
      }
  }
  
  
  class Pointer_used extends Expr
  {
      Pointer_used()
      {
          exists (ArrayExpr ae | this = ae.getArrayOffset()) or
          exists (PointerDereferenceExpr deref | this = deref.getOperand()) or
          exists (PointerAddExpr add | this = add.getAnOperand())
      }
  }
  
  class Config extends DataFlow::Configuration
  {
      Config()
      {
          this="DTraceUnsafeIndexConfig"
      }
      override predicate isSource(DataFlow::Node node)
      {
          node.asExpr() instanceof Register_access
      }
  
      override predicate isSink(DataFlow::Node node)
      {
          node.asExpr() instanceof Pointer_used
      }
  }
  
  from Config cfg,DataFlow::PathNode source,DataFlow::PathNode sink
  where cfg.hasFlowPath(source,sink)
  select source,sink
  ```

- 漏洞成因

  dtrace_dif_emulate函数是一个虚拟机，局部变量regs数组中存储了8个虚拟寄存器，由于用户可以控制DTrace的字节码，因此可以完全控制指令的操作码及操作数。对regs数组中寄存器的不当使用会引发漏洞。

- codeql查询分析
  - 该查询的第一部分限制数据源为dtrace_dif_emulate中的regs数组。
  - 第二部分要求存在对regs数组进行索引，对regs指针解引用或是其他对指针的操作的语句。

### 4.XNU_icmp_error_CVE-2018-4407

- codeql查询语句

  ```
  import cpp
  import semmle.code.cpp.dataflow.DataFlow
  import DataFlow::PathGraph
  
  class Config extends DataFlow::Configuration
  {
      Config()
      {
          this="my_test_icmp_error"
      }
  
      override predicate isSource(DataFlow::Node node)
      {
          exists(Function func|
              func.getName()="ip_input" and
              exists(node.asExpr()) and
              node.getFunction()=func
          )
      }
  
      override predicate isSink(DataFlow::Node node)
      {
          exists(Function func|
          func.getName()="icmp_error" and
          node.asParameter()=func.getParameter(0)
          )
      }
  
      override predicate isBarrier(DataFlow::Node node) {
          node.getFunction().getName() ="ip_forward"
      }
  }
  
  from Config cfg,DataFlow::PathNode source,DataFlow::PathNode sink
  where cfg.hasFlowPath(source,sink)
  select source,sink
  ```

- 漏洞成因

  第一种查询方式并没有找到真正的问题，下面不进行分析。真正导致越界写的是MH_ALIGN中的整数下溢，发生下溢的条件是len长度大于88，只要用户控制的icmplen大于80就可满足这个条件。随后icp->icmp_type = type会向伪造的地址写入type。

- codeql查询分析
  
  - 在知道了接收输入的函数是ip_input后，也知道了漏洞点就位于icmp_error中，因此要查询的就是从ip_input中开始能够到达icmp_error的数据流。
  - 源就限制为ip_input中的任意表达式。
  - 终点则是icmp_error函数的第一个参数，也就是我们可控的输入。
  - 看源码时会发现ip_forward中也调用了icmp_error，而且有3处。为了简化分析，将经过ip_forward的数据流舍弃。

