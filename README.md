# SynapseInjector

This repository contains the source code for **SynapseInjector**, a lightweight command-line utility for injecting DLLs into running processes on Windows.

## Building from Source

To compile the project, you need **Visual Studio** with the "Desktop development with C++" workload.

1.  **Clone the repository.**
2.  **Run the following command** from a Developer Command Prompt:
    ```sh
    msbuild SynapseInjector/SynapseInjector.vcxproj /p:Configuration=Release /p:Platform=x64
    ```
3.  The compiled `SynapseInjector.exe` will be located in the `SynapseInjector/x64/Release/` directory.

**NOTE:** The antivirus may flag it as a virus since computer viruses use similar program to inject code into system processes and infect the system. Make sure to disable or even create an exception for the long run.

<br>
<div align="center">
  <a href="https://github.com/brittojo7n/SynapseInjector" target="_blank">
    <img src="https://img.shields.io/badge/Synapse%20Injector-Made%20By%20Britto-5C2D91.svg?style=for-the-badge&logo=c%2B%2B&logoColor=white" alt="SynapseInjector Project Badge" />
  </a>
</div>
