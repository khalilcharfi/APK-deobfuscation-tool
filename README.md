# APK Deobfuscator

A comprehensive, production-ready APK deobfuscation pipeline that can handle various APK formats and apply multiple deobfuscation techniques.

## Features

- **Multi-format Support**: Handles APK, XAPK, and APKS files
- **Automated Tool Management**: Downloads and manages deobfuscation tools automatically
- **Robust Error Handling**: Comprehensive logging and error recovery
- **Cross-platform**: Works on Linux, macOS, and Windows
- **Production-ready**: Includes retry logic, timeout handling, and cleanup

## Prerequisites

### Required Tools
- **apktool**: APK reverse engineering tool
- **jadx**: Java decompiler
- **git**: Version control system
- **java**: Java runtime environment
- **python3**: Python interpreter
- **unzip** or **7z**: Archive extraction utility

### Optional Tools
- **adb**: Android Debug Bridge
- **frida**: Dynamic instrumentation toolkit
- **graphviz**: Graph visualization software
- **yq**: YAML processor

## Installation

1. **Clone or download the script**:
   ```bash
   # Make sure the script is executable
   chmod +x apk_deobfuscator.sh
   ```

2. **Install required dependencies**:

   **On Ubuntu/Debian**:
   ```bash
   sudo apt update
   sudo apt install apktool jadx git openjdk-11-jdk python3 unzip
   ```

   **On macOS**:
   ```bash
   brew install apktool jadx git openjdk python3
   ```

   **On Windows**:
   ```bash
   # Install via Chocolatey
   choco install apktool jadx git openjdk python3 7zip
   ```

## Usage

### Basic Usage

```bash
# Analyze a standard APK file
./apk_deobfuscator.sh --in app.apk

# Analyze with custom output directory
./apk_deobfuscator.sh --in app.apk --out analysis_results

# Analyze XAPK file
./apk_deobfuscator.sh --in app.xapk --verbose

# Analyze APKS file
./apk_deobfuscator.sh --in app.apks --out deobfuscated_app
```

### Advanced Options

```bash
# Enable verbose logging
./apk_deobfuscator.sh --in app.apk --verbose

# Keep temporary files for debugging
./apk_deobfuscator.sh --in app.apk --keep-temp

# Use custom configuration file
./apk_deobfuscator.sh --in app.apk --config custom_config.yml

# Skip device installation (if applicable)
./apk_deobfuscator.sh --in app.apk --no-install
```

### Command Line Options

| Option | Description | Required |
|--------|-------------|----------|
| `--in <file>` | Input APK/XAPK/APKS file | Yes |
| `--out <directory>` | Output directory (default: build) | No |
| `--config <file>` | Configuration file (default: deobf_config.yml) | No |
| `--no-install` | Skip device installation | No |
| `--verbose, -v` | Enable verbose logging | No |
| `--keep-temp` | Keep temporary files | No |
| `--help, -h` | Show help message | No |
| `--version` | Show version information | No |

## Output Structure

After running the script, you'll find the following structure:

```
build/
├── deobf_log.txt              # Detailed execution log
├── obf_trace.json             # Obfuscation trace data
├── analysis_report.md         # Comprehensive analysis report
├── app_extracted/             # Extracted APK contents
│   ├── smali/                 # Decompiled smali code
│   ├── res/                   # Resources
│   ├── assets/                # Assets
│   └── AndroidManifest.xml    # App manifest
└── tools/                     # Downloaded deobfuscation tools
    ├── deoptfuscator/
    ├── simplify/
    ├── Obfu-DE-Scate/
    └── ...
```

## Supported Deobfuscation Tools

The script automatically downloads and manages the following tools:

- **deoptfuscator**: Deobfuscates obfuscated code
- **simplify**: Simplifies complex code structures
- **Obfu-DE-Scate**: Advanced deobfuscation tool
- **SmaliEmu**: Smali code emulator
- **xapk-to-apk**: XAPK to APK converter
- **cfjs**: JavaScript deobfuscator
- **js-deobfuscator**: JavaScript deobfuscation tool
- **deguard**: Advanced deobfuscation framework
- **dex-translator**: DEX file translator
- **merge-apks**: APK merging utility

## Configuration

You can create a `deobf_config.yml` file to customize the behavior:

```yaml
# Example configuration file
tools:
  timeout: 300
  max_retry: 3

output:
  keep_temp: false
  verbose: false

analysis:
  generate_report: true
  include_assets: true
```

## Error Handling

The script includes comprehensive error handling:

- **Retry Logic**: Automatically retries failed operations
- **Timeout Protection**: Prevents hanging on long operations
- **Graceful Cleanup**: Removes temporary files on exit
- **Detailed Logging**: Comprehensive log files for debugging
- **Signal Handling**: Proper handling of interrupts and termination

## Troubleshooting

### Common Issues

1. **Missing Dependencies**:
   ```bash
   # Check if all required tools are installed
   which apktool jadx git java python3
   ```

2. **Permission Issues**:
   ```bash
   # Make script executable
   chmod +x apk_deobfuscator.sh
   ```

3. **Network Issues**:
   ```bash
   # Check internet connectivity for tool downloads
   ping github.com
   ```

4. **Disk Space**:
   ```bash
   # Ensure sufficient disk space
   df -h
   ```

### Debug Mode

Enable verbose logging to see detailed execution information:

```bash
./apk_deobfuscator.sh --in app.apk --verbose
```

### Keeping Temporary Files

For debugging purposes, you can keep temporary files:

```bash
./apk_deobfuscator.sh --in app.apk --keep-temp
```

## Security Considerations

- **Isolation**: Run in a controlled environment
- **Permissions**: Ensure proper file permissions
- **Network**: Be cautious with network access during analysis
- **Updates**: Keep tools updated for security patches

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This script is provided as-is for educational and research purposes. Please ensure you have proper authorization before analyzing any APK files.

## Support

For issues and questions:
1. Check the log files in the build directory
2. Review the troubleshooting section
3. Enable verbose mode for detailed output
4. Check system requirements and dependencies

## Examples

### Example 1: Basic APK Analysis
```bash
./apk_deobfuscator.sh --in myapp.apk
```

### Example 2: XAPK with Custom Output
```bash
./apk_deobfuscator.sh --in myapp.xapk --out detailed_analysis --verbose
```

### Example 3: APKS with Debug Mode
```bash
./apk_deobfuscator.sh --in myapp.apks --keep-temp --verbose
```

## Version History

- **v2.0.0**: Production-ready release with comprehensive error handling
- **v1.0.0**: Initial release with basic functionality

---

**Note**: This tool is designed for legitimate security research and educational purposes. Always ensure you have proper authorization before analyzing any APK files. 