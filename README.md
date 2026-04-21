1. check linux kernel installation:
   sudo apt-get install -y linux-headers-$(uname -r)
   
3. Run ebpf probe agent:
   python3 ebpf_probe.py
   
4. Add MCP service to GeminiCLI:
   gemini mcp add kexdr python /your path/kexdr_mcp.py

