



# 啊哈哈哈哈哈~~~ 我的, 都是我的!


## TODO
1. 增加一个选项记忆功能

2. 第二步筛选结果 应添加 全选/全不选 按钮  

3. 显示类详情? 属于哪个classloader, 内存地址之类的

4. 进行类筛选的时候, 使用的是Java.use(), 没法加载未初始化的类

5. 方法过滤结果, 要实质性的应用起来

6. 存储 被hook的方法调用栈 的逻辑是有问题的

7. 配置默认包名后, 下拉列表消失  


## tips
1. fork出来的项目改不成私有的  
2. 这个项目依赖于frida-node   
   github源码: https://github.com/frida/frida-node/blob/cec05f47e6c964be3e1015703608e7382c7cd69d/lib/index.ts   
   npmjs发布: https://www.npmjs.com/package/frida    
   
3. Pixel4 偶发性无法Attach和Spawn进程, 重启下就可以了. 具体原因不明, 但是跟Magisk无关.
   已解决. 用 进程名 替代 包名 进行hook


4. 要善用堆搜索, 这个功能太强大了. Java.choose()  idea和xcode甚至lldb调试时应该都有这个功能

5. Java.use();逻辑分析
   Java.use();返回的是一个 本质上Frida包装对象
   Java.use("java.lang.String"); 的返回值 相当于java.lang.String
   想获取对应的Class<?>对象, 需要调用 Java.use("java.lang.String").class
   但是不论是谁, 本质上都是一个 Frida包装对象
