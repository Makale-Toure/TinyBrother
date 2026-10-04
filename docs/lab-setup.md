# Lab setup (safe testing)

Never run attack simulations on your everyday machine.

1. Create a Windows 10/11 VM in VirtualBox or VMware, take a **clean snapshot**.
2. Inside the VM: install Python, Sysmon (`scripts/install_sysmon.ps1`) and TinyBrother.
3. Install Invoke-AtomicRedTeam:
   ```powershell
   IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
   Install-AtomicRedTeam -getAtomics
   ```
4. Start `tinybrother watch`, then run a test, e.g. `Invoke-AtomicTest T1059.001 -TestNumbers 1`.
5. Record whether TinyBrother raised an alert, then `Invoke-AtomicTest ... -Cleanup`.
6. Revert to the snapshot between test campaigns.

## Offline samples (no VM needed)

The [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) project
provides real `.evtx` recordings of attacks, sorted by ATT&CK tactic. They are the fastest way
to test the pipeline:

```powershell
tinybrother scan --stats .\samples\*.evtx
tinybrother scan .\samples\exec_sysmon_1_11_lolbin_rundll32_openurl_FileProtocolHandler.evtx
```
