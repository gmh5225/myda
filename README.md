# myda
General Purpose IDA Plugin. Currently, the plugin implements a wrapper around vmrun (https://docs.vmware.com/en/VMware-Fusion/13/com.vmware.fusion.using.doc/GUID-24F54E24-EFB0-4E94-8A07-2AD791F0E497.html) to facilitate remote debugging of Windows PEs from the comfort of IDA (i.e., start/suspend VM, take snapshots, revert to snapshots, copy current file to the VM, copy remote debugger stub to VM, start the remote debugger stub to the VM).

## Installation
Place main_myda.py and myda in your IDA plugins directory. Edit config.json to set the values for your VMWare/Guest VM.

## Usage
Execute the plugin and a new top-level menu, myda, will be placed after the last item you currently have (likely Help). Select "Run the VMs Script" from the VMs submenu and a chooser window will appear with a list of the VMs found in the VM directory you specified. Right-click a VM to open the context menu containing all the supported functionality. Written and tested with IDA 8.3 on macOS.

Note: Selecting 'Start remote debugger in VM' also sets debugger process options. For exe, these are entirely populated based on the config.json values, and for DLLs, there will be a pop-up to confirm the application and arguments for executing the DLL. 
