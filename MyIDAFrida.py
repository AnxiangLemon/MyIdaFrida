from string import Template
import ida_lines
import idaapi
import idc
from ida_idaapi import plugin_t
import datetime
import ida_name
import json
import os

from PyQt5 import QtCore
from PyQt5.Qt import QApplication
from PyQt5.QtWidgets import QDialog, QHBoxLayout, QVBoxLayout, QTextEdit


def clear_screen():
    window = idaapi.find_widget("Output window")
    idaapi.activate_widget(window, True)
    idaapi.process_ui_action("msglist:Clear")
    print("-" * 10, datetime.datetime.now(), "-" * 10)


def generate_file_byjsdata(data, filename) -> bool:
    try:
        open(filename, "w").write(data)
        print("生成的Frida脚本已导出到文件: ", filename)
    except Exception as e:
        print(e)
        return False
    return generate_clipboard_byjsdata(data)


def generate_clipboard_byjsdata(data) -> bool:
    clear_screen()
    print(data)
    try:
        QApplication.clipboard().setText(data)
        print("生成的Frida脚本已复制到剪贴板！")
    except Exception as e:
        print(e)
        return False
    return True


hook_function_template = """
function hook_$functionName(){
    var base_addr = Module.findBaseAddress("$soName");

    Interceptor.attach(base_addr.add($offset), {
        onEnter(args) {
            console.log("call $functionName");
            $args
        },
        onLeave(retval) {
            $result
            console.log("leave $functionName");
        }
    });
}
"""

inline_hook_template = """
function hook_$offset(){
    var base_addr = Module.findBaseAddress("$soName");

    Interceptor.attach(base_addr.add($offset), {
        onEnter(args) {
            console.log("call $offset");
            console.log(JSON.stringify(this.context));
        },
    });
}
"""

logTemplate = 'console.log("arg$index:"+args[$index]);\n'

dlopenAfter_template = """
var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
if(android_dlopen_ext != null){
    Interceptor.attach(android_dlopen_ext,{
        onEnter: function(args){
            var soName = args[0].readCString();
            if(soName.indexOf("$soName") !== -1){
                this.hook = true;
            }
        },
        onLeave: function(retval){
            if(this.hook) {
                this.hook = false;
                dlopentodo();
            }
        }
    });
}

function dlopentodo(){
    //todo
}
"""

init_template = """
function hookInit(){
    var linkername;
    var alreadyHook = false;
    var call_constructor_addr = null;
    var arch = Process.arch;
    if (arch.endsWith("arm")) {
        linkername = "linker";
    } else {
        linkername = "linker64";
    }

    var symbols = Module.enumerateSymbolsSync(linkername);
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        if (symbol.name.indexOf("call_constructor") !== -1) {
            call_constructor_addr = symbol.address;
        }
    }

    if (call_constructor_addr.compare(NULL) > 0) {
        console.log("get construct address");
        Interceptor.attach(call_constructor_addr, {
            onEnter: function (args) {
                if(alreadyHook === false){
                    const targetModule = Process.findModuleByName("$soName");
                    if (targetModule !== null) {
                        alreadyHook = true;
                        inittodo();
                    }
                }
            }
        });
    }
}

function inittodo(){
    //todo
}
"""

dump_template = """
function dump_$offset() {
    var base_addr = Module.findBaseAddress("$soName");
    var dump_addr = base_addr.add($offset);
    console.log(hexdump(dump_addr, {length: $length}));
}
"""


def generate_printArgs(argNum):
    if argNum == 0:
        return "// no args"
    else:
        temp = Template(logTemplate)
        logText = ""
        for i in range(argNum):
            logText += temp.substitute({"index": i})
            logText += "            "
        return logText


def generate_for_func(soName, functionName, address, argNum, hasReturn):
    argsPrint = generate_printArgs(argNum)

    retPrint = "// no return"
    if hasReturn:
        retPrint = "console.log(retval);"

    temp = Template(hook_function_template)
    offset = getOffset(address)
    result = temp.substitute(
        {
            "soName": soName,
            "functionName": functionName,
            "offset": hex(offset),
            "args": argsPrint,
            "result": retPrint,
        }
    )

    generate_file_byjsdata(result, "MyIDAFrida_hook.js")


def getOffset(address):
    if idaapi.get_inf_structure().is_64bit():
        return address
    else:
        return address + idc.get_sreg(address, "T")


def generate_for_inline(soName, address):
    offset = getOffset(address)
    temp = Template(inline_hook_template)
    result = temp.substitute({"soName": soName, "offset": hex(offset)})
    if idaapi.is_call_insn(address):
        callAddr = idaapi.get_name_ea(0, idc.print_operand(address, 0))
        if callAddr != idaapi.BADADDR:
            callAddress = idc.get_operand_value(address, 0)
            argnum, _ = get_argnum_and_ret(callAddress)
            argsPrint = generate_printArgs(argnum)
            result = result.replace(
                "console.log(JSON.stringify(this.context));", argsPrint
            )

    generate_file_byjsdata(result, "MyIDAFrida_inline.js")


def get_argnum_and_ret(address):
    cfun = idaapi.decompile(address)

    argnum = len(cfun.arguments)
    ret = True

    dcl = ida_lines.tag_remove(cfun.print_dcl())

    if (dcl.startswith("void ") is True) & (dcl.startswith("void *") is False):
        ret = False
    return argnum, ret


def generate_for_func_by_address(addr):
    soName = idaapi.get_root_filename()
    functionName = idaapi.get_func_name(addr)
    argnum, ret = get_argnum_and_ret(addr)
    generate_for_func(soName, functionName, addr, argnum, ret)


def generate_for_inline_by_address(addr):
    soName = idaapi.get_root_filename()
    generate_for_inline(soName, addr)


def generate_snippet(addr):
    startAddress = idc.get_func_attr(addr, idc.FUNCATTR_START)
    if startAddress == addr:
        generate_for_func_by_address(addr)
    elif startAddress == idc.BADADDR:
        print("当前传入的地址不在函数内..idc.BADADDR", startAddress)
    else:
        generate_for_inline_by_address(addr)


def generateInitCode():
    soName = idaapi.get_root_filename()
    dlopenjs = Template(dlopenAfter_template).substitute({"soName": soName})

    initjs = Template(init_template).substitute({"soName": soName})

    generate_clipboard_byjsdata(dlopenjs + "\n\n" + initjs)


def generate_dump_script(start, length):
    soName = idaapi.get_root_filename()
    dumpjs = Template(dump_template).substitute(
        {"soName": soName, "offset": hex(start), "length": hex(length)}
    )

    generate_clipboard_byjsdata(dumpjs)


class Hook(idaapi.View_Hooks):
    def view_dblclick(self, view, event):
        widgetType = idaapi.get_widget_type(view)
        if widgetType == idaapi.BWN_DISASM:
            address = idaapi.get_screen_ea()
            generate_snippet(address)


class ActionManager(object):
    def __init__(self):
        self.__actions = []

    def register(self, action):
        self.__actions.append(action)
        idaapi.register_action(
            idaapi.action_desc_t(action.name, action.description, action, action.hotkey)
        )

    def initialize(self):
        pass

    def finalize(self):
        for action in self.__actions:
            idaapi.unregister_action(action.name)


action_manager = ActionManager()


class Action(idaapi.action_handler_t):
    """
    Convenience wrapper with name property allowing to be registered in IDA using ActionManager
    """

    description = None
    hotkey = None

    def __init__(self):
        super(Action, self).__init__()

    @property
    def name(self):
        return "FridaIDA:" + type(self).__name__

    def activate(self, ctx):
        raise NotImplementedError

    def update(self, ctx):
        raise NotImplementedError


default_template = """
//这是默认的模板 
(function () {
    // @ts-ignore
    function print_arg(addr) {
        try {
            var module = Process.findRangeByAddress(addr);
            if (module != null) return "\\n"+hexdump(addr) + "\\n";
            return ptr(addr) + "\\n";
        } catch (e) {
            return addr + "\\n";
        }
    }
    // @ts-ignore
    function hook_native_addr(funcPtr, paramsNum) {
        var module = Process.findModuleByAddress(funcPtr);
        try {
            Interceptor.attach(funcPtr, {
                onEnter: function (args) {
                    this.logs = "";
                    this.params = [];
                    // @ts-ignore
                    this.logs=this.logs.concat("So: " + module.name + "  Method: [funcname] offset: " + ptr(funcPtr).sub(module.base) + "\\n");
                    for (let i = 0; i < paramsNum; i++) {
                        this.params.push(args[i]);
                        this.logs=this.logs.concat("this.args" + i + " onEnter: " + print_arg(args[i]));
                    }
                }, onLeave: function (retval) {
                    for (let i = 0; i < paramsNum; i++) {
                        this.logs=this.logs.concat("this.args" + i + " onLeave: " + print_arg(this.params[i]));
                    }
                    this.logs=this.logs.concat("retval onLeave: " + print_arg(retval) + "\\n");
                    console.log(this.logs);
                }
            });
        } catch (e) {
            console.log(e);
        }
    }
    // @ts-ignore
    hook_native_addr(Module.findBaseAddress("[filename]").add([offset]), [nargs]);
})();
"""


class Configuration:
    def __init__(self) -> None:
        self.frida_cmd = (
            """frida -U --attach-name="com.example.app" -l gen.js --no-pause"""
        )
        self.template = default_template
        if os.path.exists("IDAFrida.json"):
            self.load()

    def set_frida_cmd(self, s):
        self.frida_cmd = s
        self.store()

    def set_template(self, s):
        self.template = s
        self.store()

    def reset(self):
        self.__init__()

    def store(self):
        try:
            data = {"frida_cmd": self.frida_cmd, "template": self.template}
            open("IDAFrida.json", "w").write(json.dumps(data))
        except Exception as e:
            print(e)

    def load(self):
        try:
            data = json.loads(open("IDAFrida.json", "r").read())
            self.frida_cmd = data["frida_cmd"]
            self.template = data["template"]
        except Exception as e:
            print(e)


global_config = Configuration()


class ConfigurationUI(QDialog):
    def __init__(self, conf: Configuration) -> None:
        super(ConfigurationUI, self).__init__()
        self.conf = conf
        self.edit_template = QTextEdit()
        self.edit_template.setPlainText(self.conf.template)
        layout = QHBoxLayout()
        layout.addWidget(self.edit_template)
        self.setLayout(layout)

    def closeEvent(self, a0) -> None:
        self.conf.set_template(self.edit_template.toPlainText())
        self.conf.store()
        return super().closeEvent(a0)


class ScriptGenerator:
    def __init__(self, configuration: Configuration) -> None:
        self.conf = configuration
        self.imagebase = idaapi.get_imagebase()

    @staticmethod
    def get_idb_filename():
        return os.path.basename(idaapi.get_input_file_path())

    @staticmethod
    def get_idb_path():
        return os.path.dirname(idaapi.get_input_file_path())

    def get_function_name(self, ea):
        """
        Get the real function name
        """

        function_name = idc.demangle_name(
            idc.get_func_name(ea), idc.get_inf_attr(idc.INF_SHORT_DN)
        )

        if not function_name:
            function_name = idc.get_func_name(ea)

        if not function_name:
            function_name = idc.get_name(ea, ida_name.GN_VISIBLE)

        if not function_name:
            function_name = "UNKN_FNC_%s" % hex(ea)

        return function_name

    def generate_stub(self, repdata: dict):
        s = self.conf.template
        for key, v in repdata.items():
            s = s.replace("[%s]" % key, v)
        return s

    def generate_for_funcs(self, func_addr_list) -> str:
        stubs = []
        for func_addr in func_addr_list:
            dec_func = idaapi.decompile(func_addr)
            repdata = {
                "filename": self.get_idb_filename(),
                "funcname": self.get_function_name(func_addr),
                "offset": hex(func_addr - self.imagebase),
                "nargs": hex(dec_func.type.get_nargs()),
            }
            stubs.append(self.generate_stub(repdata))
        return "\n".join(stubs)

    def generate_for_funcs_to_file(self, func_addr_list, filename) -> bool:
        data = self.generate_for_funcs(func_addr_list)
        return generate_file_byjsdata(data, filename)


class Frida:
    def __init__(self, conf: Configuration) -> None:
        self.conf = conf


class IDAFridaMenuAction(Action):
    TopDescription = "MyIDAFrida"

    def __init__(self):
        super(IDAFridaMenuAction, self).__init__()

    def activate(self, ctx) -> None:
        raise NotImplemented

    def update(self, ctx) -> None:
        if (
                ctx.form_type == idaapi.BWN_FUNCS
                or ctx.form_type == idaapi.BWN_PSEUDOCODE
                or ctx.form_type == idaapi.BWN_DISASM
        ):
            idaapi.attach_action_to_popup(
                ctx.widget, None, self.name, self.TopDescription + "/"
            )
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


class GenerateFridaHookScript(IDAFridaMenuAction):
    description = "生成Frida hook"

    def __init__(self):
        super(GenerateFridaHookScript, self).__init__()

    def activate(self, ctx):
        gen = ScriptGenerator(global_config)
        idb_path = os.path.dirname(idaapi.get_input_file_path())
        out_file = os.path.join(idb_path, "MyIDAhook.js")
        if ctx.form_type == idaapi.BWN_FUNCS:
            selected = [idaapi.getn_func(idx).start_ea for idx in ctx.chooser_selection]

        else:
            eaaddr = idaapi.get_screen_ea()
            startAddress = idc.get_func_attr(eaaddr, idc.FUNCATTR_START)
            if startAddress == idc.BADADDR:
                print("当前传入的地址不在函数内..idc.BADADDR", startAddress)
                return
            selected = [idaapi.get_func(eaaddr).start_ea]
        gen.generate_for_funcs_to_file(selected, out_file)


class ViewFridaTemplate(IDAFridaMenuAction):
    description = "查看Frida Template"

    def __init__(self):
        super(ViewFridaTemplate, self).__init__()

    def activate(self, ctx):
        ui = ConfigurationUI(global_config)
        ui.show()
        ui.exec_()


class GenerateFridaInitScript(IDAFridaMenuAction):
    description = "生成Frida Init"

    def __init__(self):
        super(GenerateFridaInitScript, self).__init__()

    def activate(self, ctx):
        generateInitCode()


class GenerateFridaDumpScript(IDAFridaMenuAction):
    description = "生成Frida Dump"

    def __init__(self):
        super(GenerateFridaDumpScript, self).__init__()

    def activate(self, ctx):
        if ctx.form_type == idaapi.BWN_DISASM:
            start = idc.read_selection_start()
            end = idc.read_selection_end()
            if (start != idaapi.BADADDR) and (end != idaapi.BADADDR):
                length = end - start
                generate_dump_script(start, length)


myViewHook = Hook()
myViewHook.hook()

action_manager.register(GenerateFridaHookScript())
action_manager.register(GenerateFridaDumpScript())
action_manager.register(GenerateFridaInitScript())
action_manager.register(ViewFridaTemplate())
