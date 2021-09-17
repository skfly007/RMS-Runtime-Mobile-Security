

let tempObj={
    "com.skfly.xposedtest.MainActivity":[
    {
        "ui_name": "protected void onCreate(android.os.Bundle)",
        "name": "onCreate",
        "args": "\"android.os.Bundle\""
    },
    {
        "ui_name": "public void 输出内容(java.lang.String)",
        "name": "输出内容",
        "args": "\"java.lang.String\""
    }]
};


hook_classes_and_methods_Android(tempObj,true);


Java.perform(function () {
    var classname = "com.skfly.xposedtest.MainActivity$8";
    var classmethod = "onClick";
    var methodsignature = "public void onClick(android.view.View)";
    var hookclass = Java.use(classname);

    hookclass.onClick.overload("android.view.View").implementation = function (v0) {
        send("[Call_Stack]\nClass: " +classname+"\nMethod: "+methodsignature+"\n");
        var ret = this.onClick(v0);

        var s="";
        s=s+"[Hook_Stack]\n"
        s=s+"Class: "+classname+"\n"
        s=s+"Method: "+methodsignature+"\n"
        s=s+"Called by: "+Java.use('java.lang.Exception').$new().getStackTrace().toString().split(',')[1]+"\n"
        s=s+"Input: "+eval(args)+"\n"
        s=s+"Output: "+ret+"\n"

        send(s);

        return ret;
    };
});

