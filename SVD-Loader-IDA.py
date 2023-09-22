'''
IDAPython plugin

Useful for reversing firmwares.
Author:
    (c) Mathieu Renard <dark@gotohack.org>
    (c) Thomas Roth <thomas.roth@leveldown.de>

License: GPLv3
'''
import logging
from collections import namedtuple
import idc
import idaapi
import idautils
from idaapi import simplecustviewer_t

def genSegAlign(ea, alignment):
    if hasattr(idc, "set_segm_attr") and callable(getattr(idc, "set_segm_attr")):
        return idc.set_segm_attr(ea, 20, alignment)

def genAddStruc(index, name):
    if hasattr(idc, "add_struc") and callable(getattr(idc, "add_struc")):
        return idc.add_struc(index, name, 0)

try:
    from idaapi import Choose2
except:
    from idaapi import Choose as Choose2
    idc.RenameSeg = idc.set_segm_name
    idc.SetSegClass = idc.set_segm_class
    idc.SegAlign = genSegAlign
    idc.SetSegmentAttr = idc.set_segm_attr
    idc.GetStrucIdByName = ida_struct.get_struc_id
    idc.DelStruc = idc.del_struc
    idc.AddStruc = genAddStruc
    idc.AddStrucEx = idc.add_struc
    idc.AddStrucMember = idc.add_struc_member
    idc.SetMemberComment = idc.set_member_cmt
    idc.MakeStructEx = idc.create_struct
    idc.GetStrucSize = ida_struct.get_struc_size
    idc.MakeNameEx = idc.set_name
    idc.GetFunctionName = idc.get_func_name
    idc.isCode = ida_bytes.is_code
    ida_bytes.getFlags = ida_bytes.get_full_flags
    idc.MakeCode = idc.create_insn
    idc.MakeFunction = ida_funcs.add_func
    idc.Jump = ida_kernwin.jumpto
    ida_auto.autoWait = ida_auto.auto_wait
    idc.ItemHead = ida_bytes.get_item_head	
    idc.ItemEnd = ida_bytes.get_item_end	
    idc.ItemSize = idc.get_item_size	
    idc.AnalyzeRange = idc.plan_and_wait
    idc.MakeUnkn = ida_bytes.del_items
    idc.DOUNK_EXPAND = ida_bytes.DELIT_EXPAND
    ida_auto.analyze_area = ida_auto.plan_and_wait


from helpers import *

from cmsis_svd.parser import SVDParser
#from __future__ import print_function

logger = logging.getLogger(__name__)


#from PyQt5.QtWidgets import QWidget, QPushButton, QLabel, QHBoxLayout, QVBoxLayout, QApplication, QTreeWidget, QTreeWidgetItem, QTreeWidgetItem




def get_seg_list(type='DATA'):
    seg_list = []
    for seg in Segments():
        print('%x-%x'%(SegStart(seg),SegEnd(seg)))
        seg_list.append({'start':SegStart(seg),'end':SegEnd(seg)})
    return seg_list

def get_xref_to_seg(seg):
    start = SegStart(seg)
    end = SegEnd(seg)
    for ea in idautils.Heads(start, end):
        gen_xrefs = XrefsTo(ea, 0)
        for xx in gen_xrefs:
            print(hex(ea), hex(xx.frm))


def RenameFunction(name, item):
    start_addr = idc.get_func_attr(item,idc.FUNCATTR_START)
    cur_name = idc.GetFunctionName(item)
    new_name = "%s_%08x" % (name, start_addr)
    if cur_name.startswith(name) == False:
        print("Renaiming function @ 0x%x: %s => %s " % (start_addr, cur_name, new_name))
        idc.set_name(start_addr, new_name, 0x01)


class NameSpaceForm(idaapi.PluginForm):

    def __init__(self, peripherals=None):
        idaapi.PluginForm.__init__(self)
        self.peripherals = peripherals
        self.__name = "Peripherals"
        self.peripherals = peripherals

    def OnCreate(self, form):
        self.myform = form
        self.parent = self.FormToPyQtWidget(self.myform)
        self.PopulateForm()

    def PopulateForm(self):
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(QtWidgets.QLabel(self.__name))
        self.tree = QtWidgets.QTreeWidget()
        layout.addWidget(self.tree)
        self.tree.setHeaderLabels(("Peripherals","Function Name","Address","Instructions"))
        self.tree.setColumnCount(4)
        self.tree.setColumnWidth(0, 200)
        self.tree.setColumnWidth(1, 300)
        self.tree.setColumnWidth(2, 200)
        self.tree.setColumnWidth(3, 200)
        self.tree.setSortingEnabled(True)
        self.tree.itemClicked.connect(self.OnClick)
        self.PopulateTree()
        self.parent.setLayout(layout)

    def Show(self):
        idaapi.PluginForm.Show(self, self.__name)


    def PopulateTree(self):
        print("Populating tree...")
        #self.tree.clear()
        
        root = QtWidgets.QTreeWidgetItem(self.tree)
        for p in self.peripherals:
            p_item = QtWidgets.QTreeWidgetItem(root)
            p_item.setText(0, p.name)
            xrefs = XrefsTo(p.base_address, 0)
            last_func = None
            last_p_func = None
            for x in xrefs:
                item    = idc.ItemHead(x.frm)
                itemend = idc.ItemEnd(x.frm)
                
                print("Name: %s XRef: 0x%08x Head: 0x%08x End: 0x%08x" % (p.name, x.frm, item, itemend))
                if item == idc.BADADDR:
                    print("[!] BADADDR @ 0x%08x: (%x)!" % (x.frm, item))
                    break

                idc.MakeUnkn(item, idc.DOUNK_EXPAND)
                if idc.isCode(ida_bytes.getFlags(item)) == 0:
                    if idc.MakeCode(item) == 0:
                        print("[!] fail to decode instr @ 0x%08x!" % item)
                    ida_auto.autoWait()

                if idc.GetFunctionName(item) == "":
                    if idc.MakeFunction(item) == 0:
                        print("[!] fail to create function @ 0x%08x!" % item)
                ida_auto.autoWait()
                
                RenameFunction(p.name, item)
                ida_auto.autoWait()
                func_name = idc.GetFunctionName(item)

                # Give IDA a chance to analyze the new code or else we won't be able to create a
                ida_auto.analyze_area(item, itemend)
                
                p_func = QtWidgets.QTreeWidgetItem(p_item)
                p_func.setText(1, "%s" % func_name)
                
                p_addr = QtWidgets.QTreeWidgetItem(p_item)
                p_addr.setText(2, "0x%08x" % item)
                
                p_inst = QtWidgets.QTreeWidgetItem(p_item)
                p_inst.setText(3,idc.GetDisasm(item))               
                
                last_p_func = p_func


        print("Done")

    def OnClose(self, form):
        global nvw
        del nvw
        print("SVDLoader closed")
        return 1

    def OnClick(self, it, col):
        if col == 2: #FIXME
            idc.Jump(int(it.text(col),16))

class BadInputError(Exception):
    pass


class SelectSVDFile(idaapi.Form):
    def __init__(self):
        idaapi.Form.__init__(self, """STARTITEM 0
SVD File
<##SVD file path:{path}>
""",
                             {
                                 'path': idaapi.Form.FileInput(open=True),
                             })
    def OnFormChange(self, fid):
        return 1


def prompt_for_svd():
    ''' :returns: SVD file path, or raises BadInputError '''
    f = SelectSVDFile()
    f.Compile()
    f.path.value = ""
    ok = f.Execute()
    if ok != 1:
        raise BadInputError('[!] user cancelled')
    path = f.path.value
    if path == "" or path is None:
        raise BadInputError('[!] bad path provided')

    if not os.path.exists(path):
        raise BadInputError('[!] file doesn\'t exist')

    f.Free()
    return path

def add_segment(addr, seglen, name,seg_type='Peripheral', perms=(4 | 2)):  # READ | WRITE
    print("[+] creating seg: 0x%08X: %d" % (addr, 4))
    if not idc.AddSeg(addr, addr + seglen, 0, 1, 0, idaapi.scPub):
        logger.error('[!] failed to add segment: 0x%x', addr)
        return -1
    if not idc.RenameSeg(addr, name):
        logger.warning('[!] failed to rename segment: %s' % (seg_type, name))

    if not idc.SetSegClass(addr, seg_type):
        logger.warning('[!] failed to set segment class %s : %s', name)

    if not idc.SegAlign(addr, idc.saRelPara):
        logger.warning('[!] failed to align segment: %s', name)
    if not idc.SetSegmentAttr(addr, idc.SEGATTR_PERM, perms ):
        logger.warning('[!] failed to set permitions for segment class: %s', name)
    return 1




def main(argv=None):
    SVDLoaderPlugin.header()

    if argv is None:
        argv = sys.argv[:]
    try:
        svd_path = prompt_for_svd()
    except BadInputError:
        logger.error('[!] bad input, exiting...')
        return -1

    print("[+] Loading SVD file...")
    parser = SVDParser.for_xml_file(svd_path)
    print("\tDone!")

    # CM0, CM4, etc
    cpu_type = parser.get_device().cpu.name
    # little/big
    cpu_endian = parser.get_device().cpu.endian

    default_register_size = parser.get_device().size

    # Not all SVDs contain these fields
    if cpu_type and not cpu_type.startswith("CM"):
        print("[!] Currently only Cortex-M CPUs are supported.")
        print("    Supplied CPU type was: " + cpu_type)
        sys.exit(1)

    if cpu_endian and cpu_endian != "little":
        print("[!] Currently only little endian CPUs are supported.")
        print("    Supplied CPU endian was: " + cpu_endian)
        sys.exit(1)


    print("[+] Geting peripherals...")
    peripherals = parser.get_device().peripherals
    print("\tDone!")
    
    print("[+] Generating memory regions...")
    # First, we need to generate a list of memory regions.
    # This is because some SVD files have overlapping peripherals...
    memory_regions = []
    for peripheral in peripherals:
        start = peripheral.base_address
        length = peripheral.address_block.offset + peripheral.address_block.size
        end = peripheral.base_address + length
        memory_regions.append(MemoryRegion(peripheral.name, start, end))

    memory_regions = reduce_memory_regions(memory_regions)
    # Create segment:
    for r in memory_regions:
        #print(r.start, r.length(), r.name)
        add_segment(r.start, r.length(), r.name)
    print("\tDone!")

    # Create peripherals:
    for peripheral in peripherals:
        print("[+] Creating %s:\t0x%08x" % (peripheral.name, peripheral.base_address))
        if(len(peripheral.registers) == 0):
            print("\t\tNo registers.")
            continue
        # Iterage registers to get size of peripheral
        # Most SVDs have an address-block that specifies the size, but
        # they are often far too large, leading to issues with overlaps.
        length = calculate_peripheral_size(peripheral, default_register_size)
        peripheral_name = "struct_"+peripheral.name
        # Generate structure for the peripheral
        p_sid = idc.GetStrucIdByName(peripheral_name)
        if p_sid != -1:
            idc.DelStruc(p_sid)
        p_sid = idc.AddStrucEx(-1, peripheral_name, 0)

        peripheral_start = peripheral.base_address
        peripheral_end = peripheral_start + length

        for register in peripheral.registers:
            r_flag = 0
            #print(register.to_dict())
            if(register.size):
                rs = register.size / 8
                if rs == 1:
                    r_flag = (FF_BYTE|FF_DATA) &0xFFFFFFFF
                elif rs == 2:
                    r_flag = (FF_WORD|FF_DATA) &0xFFFFFFFF
                elif rs == 4:
                    r_flag = (FF_DWORD|FF_DATA) &0xFFFFFFFF
                elif rs == 8:
                    r_flag = (FF_QWRD|FF_DATA) &0xFFFFFFFF
                else:
                    raise "FU!"
                # Generate structure for the register
                print("\t %s, %d, %x, %d" % (register.name, register.address_offset, r_flag, rs))
                r_name = register.name
                idc.AddStrucMember(p_sid, r_name , register.address_offset,flag=r_flag,typeid=-1,nbytes=register.size/8)
                idc.SetMemberComment(p_sid, register.address_offset, register.description, 1)
                idc.MakeStructEx(peripheral_start, idc.GetStrucSize(p_sid), peripheral_name)
                idc.MakeNameEx(peripheral_start,peripheral.name, SN_AUTO | SN_NOCHECK)
    print("\tDone!")

    global nvw
    try:
        nvw.PopulateForm()
    except:
        nvw = NameSpaceForm(peripherals)
    nvw.Show()


class SVDLoaderPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Add a segment to an IDA .svd from a file."
    help = "Add a segment to an IDA .svd from a file."
    wanted_name = "SVDLoader"
    wanted_hotkey = "Alt-F8"

    @staticmethod
    def header():
        """
            help!
        """
        print("-*" * 40)
        print("")
        print("         SVD Loader ")
        print("             (c) Mathieu Renard <dark@gotohack.io>")
        print("             (c) Thomas Roth <thomas.roth@leveldown.de>")
        print("")
        print("-" * 80)
        print("\t License: GPLv3")
        print("Help:")
        print("see   https://www.github.com/gotohack/SVDLoader/docs/")
        print("-*" * 40)
        return

    def init(self):
        self.icon_id = 0
        return idaapi.PLUGIN_OK

    def run(self, arg):
        main()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return SVDLoaderPlugin()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
