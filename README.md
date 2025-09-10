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
