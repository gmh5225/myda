import subprocess
import struct
import idaapi
import idautils
import pefile
import os
import idc
import json

def no_dynamic_base(path):

    o = os.path.basename(path)
    s = "s_" + o
    s_path = os.path.dirname(path) + "/" + s
    pe = pefile.PE(path)
    pe.write(s_path)

    pe = pefile.PE(s)
    if pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE:

        file = open(s_path, "r+b")
        # DllCharacteristics offset
        file.seek(pe.OPTIONAL_HEADER.get_file_offset() + 0x46)
        # Get the dynamic base out of there
        word = struct.pack("<H", pe.OPTIONAL_HEADER.DllCharacteristics ^ 0x40)
        file.write(word)
        file.close()

    return s_path

def debug_params(debug_type, mal_path, dll, guest_ip, guest_debug_port):
    idaapi.auto_wait()
    idaapi.load_debugger(debug_type, True)
    idaapi.set_process_options(mal_path, "", "", guest_ip, "", guest_debug_port)
    if dll:
        dll_host = idaapi.ask_str("C:\\Windows\\System32\\rundll32.exe", 1, "DLL Host ")
        dll_host_args = idaapi.ask_str(mal_path + "#1", 1, "DLL Host Args ")
        idaapi.set_process_options(dll_host, dll_host_args, "", guest_ip, "", guest_port)
    idaapi.set_root_filename(mal_path)


def vmrun_it(vm, vm_cmd):

    debug_stub_path = idc.idadir() + "/dbgsrv/"
    debug_stub_win64 = "win64_remote64.exe"
    debug_stub_win32 = "win32_remote.exe"

    # read config file
    config_path = os.path.dirname(__file__) + '/config.json'
    config_json = json.load(open(config_path))
    vmware_app_path = config_json["vmware_app_paths"]["vmware_path"]
    vmrun_path = config_json["vmware_app_paths"]["vmrun_path"]
    guest_mal_path_exe = config_json["guest_paths"]["guest_mal_path_exe"]
    guest_mal_path_dll = config_json["guest_paths"]["guest_mal_path_dll"]
    guest_debug_path_win = config_json["guest_paths"]["guest_debug_path_win"]
    guest_win_user = config_json["guest_creds"]["guest_win_user"]
    guest_win_pass = config_json["guest_creds"]["guest_win_pass"]
    guest_ip = config_json["guest_network_config"]["guest_ip"]
    guest_debug_port = config_json["guest_network_config"]["guest_debug_port"]

    host_mal_path = idaapi.get_input_file_path()

    print("vmrun runner executing %s on %s\n" % (vm_cmd, vm))

    # determine file properties and set paths
    file_type = idaapi.inf_get_filetype()
    arch_type = idaapi.inf_get_app_bitness()
    is_dll = False
    if file_type == idaapi.f_PE:
        peheader = idautils.peutils_t()
        # check if DLL
        if struct.unpack('<H', peheader.header()[0x16:0x18])[0] & 0x2000:
            # this is a dll
            is_dll = True
            guest_mal_path = guest_mal_path_dll
        else:
            guest_mal_path = guest_mal_path_exe
        if arch_type == 0x40:
            debug_stub_path += debug_stub_win64
        elif arch_type == 0x20:
            debug_stub_path += debug_stub_win32
        debug_type = "win32"
        guest_debug_path = guest_debug_path_win

    # set debug params

    match vm_cmd:
        case "vm_vmware_start":
            print("Starting VMWare...")
            # start vmware
            subprocess.Popen([vmware_app_path])

        case "vm_start":
            out = subprocess.Popen([vmrun_path, "start", vm])
            print("%s started\n" % vm)

        case "vm_suspend":
            out = subprocess.Popen([vmrun_path, "suspend", vm])
            print("%s suspended\n" % vm)

        case "vm_revert":
            snapshot_name = idaapi.ask_str("pre_detonation", 1, "Name of snapshot to revert to ")
            out = subprocess.Popen([vmrun_path, "revertToSnapshot", vm, snapshot_name])
            print("Snapshot reverted to %s\n" % snapshot_name)

        case "vm_take_snapshot":
            snapshot_name = idaapi.ask_str("infected", 1, "Name of new snapshot ")
            out = subprocess.Popen([vmrun_path, "snapshot", vm, snapshot_name])
            print("Saved snapshot as %s\n" % snapshot_name)

        case "vm_copy_debug_stub":
            out = subprocess.Popen([vmrun_path, "-T", "fusion", "-gu", guest_win_user, "-gp", guest_win_pass, "CopyFileFromHostToGuest", vm, debug_stub_path, guest_debug_path])
            print("Copied debug stub %s to %s in Guest VM\n" % (debug_stub_path, guest_debug_path))

        case "vm_start_debug_stub_in_vm":
            debug_params(debug_type, guest_mal_path, is_dll, guest_ip, guest_debug_port)
            if debug_type == "win32":
                debug_run = subprocess.Popen(
                [vmrun_path, "-T", "fusion", "-gu", guest_win_user, "-gp", guest_win_pass, "runPrograminGuest", vm,
                "-activeWindow", "-interactive", "-noWait", guest_debug_path])
            print("Launched debug stub in VM\n")

        case "vm_copy_this_file_to_guest":
            # edit mal file to disable dynamic base, if requested
            if idaapi.ask_yn(idaapi.ASKBTN_YES, "Copy with dynamic base disabled?") == idaapi.ASKBTN_YES:
                s_path = no_dynamic_base(host_mal_path)
                host_mal_path = s_path
            out = subprocess.Popen([vmrun_path, "-T", "fusion", "-gu", guest_win_user, "-gp", guest_win_pass, "CopyFileFromHostToGuest", vm, host_mal_path, guest_mal_path])
            print("Copied %s to %s" % (host_mal_path, guest_mal_path))

        case _:
            print("vm_cmd %s not recognized\n" % vm_cmd)
