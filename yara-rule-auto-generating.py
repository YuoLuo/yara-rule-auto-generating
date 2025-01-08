#!/usr/bin/env python3
import os
import hashlib
import argparse
import re
import magic
import pefile
import elftools.elf.elffile
import macholib.MachO
import struct
from datetime import datetime
from typing import List, Dict, Optional

class FileAnalyzer:
    """基础文件分析类"""
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.file_data = self._read_file()
        
    def _read_file(self) -> bytes:
        with open(self.file_path, 'rb') as f:
            return f.read()
            
    def get_strings(self) -> List[str]:
        """提取文件中的字符串"""
        strings = []
        # ASCII字符串 (最少4个字符)
        ascii_strings = re.findall(b'[\x20-\x7E]{4,}', self.file_data)
        # Unicode字符串
        unicode_strings = re.findall(b'(?:[\x20-\x7E]\x00){4,}', self.file_data)
        
        strings.extend([s.decode('ascii', errors='ignore') for s in ascii_strings])
        strings.extend([s.decode('utf-16le', errors='ignore') for s in unicode_strings])
        return strings

class PEAnalyzer(FileAnalyzer):
    """Windows PE文件分析器"""
    def __init__(self, file_path: str):
        super().__init__(file_path)
        self.pe = pefile.PE(file_path)
        
    def get_specific_features(self) -> Dict:
        features = {
            'sections': [],
            'imports': [],
            'exports': [],
            'entry_point': self.pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'image_base': self.pe.OPTIONAL_HEADER.ImageBase,
            'subsystem': self.pe.OPTIONAL_HEADER.Subsystem
        }
        
        # 收集区段信息
        for section in self.pe.sections:
            features['sections'].append({
                'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                'characteristics': section.Characteristics,
                'entropy': section.get_entropy()
            })
            
        # 收集导入函数
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    if imp.name:
                        features['imports'].append(f"{dll_name}:{imp.name.decode('utf-8', errors='ignore')}")
                        
        # 收集导出函数
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    features['exports'].append(exp.name.decode('utf-8', errors='ignore'))
                    
        return features

class ELFAnalyzer(FileAnalyzer):
    """Linux ELF文件分析器"""
    def __init__(self, file_path: str):
        super().__init__(file_path)
        with open(file_path, 'rb') as f:
            self.elf = elftools.elf.elffile.ELFFile(f)
            
    def get_specific_features(self) -> Dict:
        features = {
            'sections': [],
            'symbols': [],
            'dynamic': [],
            'entry_point': self.elf.header.e_entry
        }
        
        # 收集区段信息
        for section in self.elf.iter_sections():
            features['sections'].append({
                'name': section.name,
                'type': section.header.sh_type,
                'flags': section.header.sh_flags
            })
            
        # 收集符号表
        symbol_tables = ['.symtab', '.dynsym']
        for section_name in symbol_tables:
            symbol_section = self.elf.get_section_by_name(section_name)
            if symbol_section:
                for symbol in symbol_section.iter_symbols():
                    if symbol.name:
                        features['symbols'].append(symbol.name)
                        
        # 收集动态链接信息
        dynamic = self.elf.get_section_by_name('.dynamic')
        if dynamic:
            for tag in dynamic.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    features['dynamic'].append(tag.needed)
                    
        return features

class MachOAnalyzer(FileAnalyzer):
    """macOS Mach-O文件分析器"""
    def __init__(self, file_path: str):
        super().__init__(file_path)
        self.macho = macholib.MachO.MachO(file_path)
        
    def get_specific_features(self) -> Dict:
        features = {
            'segments': [],
            'imports': [],
            'entry_point': 0
        }
        
        for header in self.macho.headers:
            # 收集段信息
            for segment in header.commands:
                if segment[0].cmd in [macholib.MachO.LC_SEGMENT, macholib.MachO.LC_SEGMENT_64]:
                    features['segments'].append({
                        'name': segment[1].segname.decode('utf-8', errors='ignore'),
                        'vmaddr': segment[1].vmaddr,
                        'vmsize': segment[1].vmsize
                    })
                    
                # 收集导入信息
                elif segment[0].cmd == macholib.MachO.LC_LOAD_DYLIB:
                    features['imports'].append(segment[2].decode('utf-8', errors='ignore'))
                    
                # 获取入口点
                elif segment[0].cmd == macholib.MachO.LC_MAIN:
                    features['entry_point'] = segment[1].entryoff
                    
        return features

class YaraRuleGenerator:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.file_name = os.path.basename(file_path)
        self.file_size = os.path.getsize(file_path)
        self.file_type = magic.from_file(file_path)
        self.md5 = self._get_file_hash('md5')
        self.sha256 = self._get_file_hash('sha256')
        
        # 根据文件类型选择适当的分析器
        self.analyzer = self._get_analyzer()
        if self.analyzer:
            self.specific_features = self.analyzer.get_specific_features()
            self.strings = self.analyzer.get_strings()
        else:
            self.specific_features = {}
            self.strings = []
            
        self.unique_strings = self._get_unique_strings()

    def _get_file_hash(self, hash_type: str) -> str:
        """计算文件哈希值"""
        hash_obj = hashlib.new(hash_type)
        with open(self.file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

    def _get_analyzer(self) -> Optional[FileAnalyzer]:
        """根据文件类型返回相应的分析器"""
        try:
            with open(self.file_path, 'rb') as f:
                magic_bytes = f.read(4)
                
            # PE文件
            if magic_bytes.startswith(b'MZ'):
                return PEAnalyzer(self.file_path)
            # ELF文件
            elif magic_bytes.startswith(b'\x7fELF'):
                return ELFAnalyzer(self.file_path)
            # Mach-O文件
            elif magic_bytes in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', 
                               b'\xca\xfe\xba\xbe', b'\xcf\xfa\xed\xfe']:
                return MachOAnalyzer(self.file_path)
            else:
                return FileAnalyzer(self.file_path)
        except Exception as e:
            print(f"Warning: Could not create specific analyzer: {str(e)}")
            return FileAnalyzer(self.file_path)

    def _get_unique_strings(self) -> List[str]:
        """获取唯一的、有意义的字符串"""
        unique_strings = set()
        
        for string in self.strings:
            # 过滤掉太短或太长的字符串
            if 4 <= len(string) <= 100:
                # 过滤掉只包含简单重复字符的字符串
                if not re.match(r'^(.)\1+$', string):
                    # 过滤掉常见的系统路径和无意义字符串
                    if not any(p in string.lower() for p in ['/usr/lib/', 'c:\\windows\\', '/system/']):
                        unique_strings.add(string)
        
        return list(unique_strings)[:20]  # 限制返回的字符串数量

    def _generate_specific_conditions(self) -> str:
        """根据文件类型生成特定的条件"""
        conditions = []
        
        if isinstance(self.analyzer, PEAnalyzer):
            # PE文件特定条件
            conditions.append('uint16(0) == 0x5A4D')  # MZ头
            if 'sections' in self.specific_features:
                for section in self.specific_features['sections']:
                    if section['entropy'] > 7.0:  # 高熵区段可能表示加密或压缩
                        conditions.append(f'math.entropy(0, filesize) >= 7.0')
                        break
            
        elif isinstance(self.analyzer, ELFAnalyzer):
            # ELF文件特定条件
            conditions.append('uint32(0) == 0x464C457F')  # ELF头
            if self.specific_features.get('dynamic'):
                for lib in self.specific_features['dynamic'][:3]:  # 限制数量
                    conditions.append(f'contains_elf_import("{lib}")')
            
        elif isinstance(self.analyzer, MachOAnalyzer):
            # Mach-O文件特定条件
            conditions.append('(uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF or ' +
                            'uint32(0) == 0xCAFEBABE or uint32(0) == 0xCFFAEDFE)')
            if self.specific_features.get('segments'):
                conditions.append(f'contains_macho_segment("__TEXT")')
        
        return ' and\n        '.join(conditions) if conditions else 'true'

    def generate_rule(self) -> str:
        """生成YARA规则"""
        rule_name = f"malware_{self.md5[:8]}"
        current_date = datetime.now().strftime("%Y-%m-%d")
        
        rule = f"""rule {rule_name}
{{
    meta:
        description = "Auto-generated rule for {self.file_name}"
        author = "YaraRuleGenerator"
        date = "{current_date}"
        hash_md5 = "{self.md5}"
        hash_sha256 = "{self.sha256}"
        file_type = "{self.file_type}"
        file_size = "{self.file_size}"

    strings:
        $file_size = {{"""
        
        # 添加文件大小特征
        size_hex = '{:08x}'.format(self.file_size)
        rule += ' '.join([size_hex[i:i+2] for i in range(0, len(size_hex), 2)])
        rule += "}}\n"
        
        # 添加字符串特征
        for i, string in enumerate(self.unique_strings):
            # 转义特殊字符
            string = string.replace('\\', '\\\\').replace('"', '\\"')
            rule += f'        $string_{i} = "{string}"\n'
            
        # 添加特定文件类型的特征
        if isinstance(self.analyzer, PEAnalyzer):
            for i, imp in enumerate(self.specific_features.get('imports', [])[:10]):
                rule += f'        $imp_{i} = "{imp}"\n'
        elif isinstance(self.analyzer, ELFAnalyzer):
            for i, sym in enumerate(self.specific_features.get('symbols', [])[:10]):
                rule += f'        $sym_{i} = "{sym}"\n'
        elif isinstance(self.analyzer, MachOAnalyzer):
            for i, imp in enumerate(self.specific_features.get('imports', [])[:10]):
                rule += f'        $imp_{i} = "{imp}"\n'
        
        rule += """
    condition:
        """
        
        # 添加基本条件
        rule += self._generate_specific_conditions()
        
        # 添加字符串匹配条件
        min_strings = min(len(self.unique_strings) // 2, 5)
        if min_strings > 0:
            rule += f" and {min_strings} of ($string_*)"
        
        # 添加特定文件类型的条件
        if isinstance(self.analyzer, PEAnalyzer) and self.specific_features.get('imports'):
            rule += f" and 2 of ($imp_*)"
        elif isinstance(self.analyzer, ELFAnalyzer) and self.specific_features.get('symbols'):
            rule += f" and 2 of ($sym_*)"
        elif isinstance(self.analyzer, MachOAnalyzer) and self.specific_features.get('imports'):
            rule += f" and 2 of ($imp_*)"
        
        rule += """
}}"""
        return rule

def main():
    parser = argparse.ArgumentParser(description='Generate YARA rules from files')
    parser.add_argument('file_path', help='Path to the target file')
    parser.add_argument('-o', '--output', help='Output file path for the YARA rule')
    parser.add_argument('--min-entropy', type=float, default=7.0, 
                       help='Minimum entropy threshold for identifying encrypted/compressed sections')
    args = parser.parse_args()

    try:
        generator = YaraRuleGenerator(args.file_path)
        rule = generator.generate_rule()
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(rule)
            print(f"YARA rule has been written to {args.output}")
        else:
            print(rule)
            
    except Exception as e:
        print(f"Error: {str(e)}")
        return 1

def install_dependencies():
    """检查并安装必要的依赖"""
    try:
        import pkg_resources
        required = {'pefile', 'pyelftools', 'macholib', 'python-magic'}
        installed = {pkg.key for pkg in pkg_resources.working_set}
        missing = required - installed
        
        if missing:
            print("Installing missing dependencies...")
            import subprocess
            subprocess.check_call(['pip', 'install'] + list(missing))
            print("Dependencies installed successfully.")
    except Exception as e:
        print(f"Warning: Could not install dependencies: {str(e)}")
        print("Please install the following packages manually:")
        print("pip install pefile pyelftools macholib python-magic")

if __name__ == "__main__":
    install_dependencies()
    main()
