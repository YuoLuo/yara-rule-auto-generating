# yara--auto-generating
垃圾制造者
这个YARA 规则生成器现在具有以下特点：

跨平台文件分析:

Windows PE 文件分析
Linux ELF 文件分析
macOS Mach-O 文件分析
通用二进制文件分析


特定平台特征提取:

PE文件:

区段信息和熵值分析
导入表和导出表分析
入口点特征


ELF文件:

区段分析
符号表分析
动态链接信息


Mach-O文件:

段信息分析
导入库分析
入口点特征




增强的字符串分析:

ASCII和Unicode字符串提取
自动过滤系统路径和常见字符串
基于熵值的字符串质量评估


智能规则生成:

根据文件类型自动选择合适的特征
动态调整匹配条件
自动处理特殊字符和编码



使用方法:
bashCopy# 基本使用
python3 yara_generator.py <target_file>

# 保存规则到文件
python3 yara_generator.py <target_file> -o rule.yar

# 设置熵值阈值
python3 yara_generator.py <target_file> --min-entropy 6.5
依赖安装:
bashCopy# 脚本会自动尝试安装依赖，也可以手动安装
pip install pefile pyelftools macholib python-magic
