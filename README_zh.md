# HydroxAI Compliance SDK

**语言**: [English](README.md) | [中文](README_zh.md)

[![PyPI version](https://badge.fury.io/py/hydroxai.svg)](https://badge.fury.io/py/hydroxai)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

HydroxAI Compliance SDK 是一个开源的 Python 包，用于测试 AI 模型的安全性和合规性。它帮助您检测 AI 应用程序中的安全风险，包括提示注入、越狱、幻觉和超出角色的响应等。

## 什么是 HydroxAI Compliance？

[compliance.hydrox.ai](https://compliance.hydrox.ai) 是一个全面的 AI 安全测试平台，提供多种接口来测试模型的输入内容合规性和安全性。它保护免受各种内容输出风险，包括对智能体的攻击、MCP、提示泄露、提示注入、越狱、幻觉等。

**HydroxAI Compliance SDK** 是 [compliance.hydrox.ai](https://compliance.hydrox.ai) 的开源版本，包含核心安全测试功能。我们持续维护和更新此仓库，添加新功能。我们欢迎社区开发者贡献建议和改进！

## 为什么这很重要？

AI 安全至关重要，不容忽视。如果您的产品需要在专业和准确的环境中使用，安全测试是必不可少的。适当的测试有助于确保您的 AI 系统按预期运行，不会产生有害或不当的内容。

## 功能特性

- **聊天机器人测试**: 测试基于 Web 的聊天机器人的合规性和安全性
- **API 测试**: 通过 API 端点测试您部署的模型
- **函数测试**: 测试单个函数或智能体对恶意输入的处理
- **自定义载荷**: 添加您自己的测试提示和场景
- **自动化扫描**: 跨多个场景扩展测试

## 安装

使用 pip 安装包：

```bash
pip install hydroxai
```

## 快速开始

```python
from hydroxai.compliance import Scanner

# 测试网页聊天机器人
Scanner().scan_chatbot("https://chatgpt.com")
```

## 使用示例

### 1. 聊天机器人测试

测试基于 Web 的聊天机器人，检查您的聊天机器人是否输出超出角色或恶意内容：

```python
from hydroxai.compliance import Scanner

Scanner().scan_chatbot("https://chatgpt.com")
```

您也可以将自己聊天机器人的 HTML 元素信息添加到 `data/selectors.json` 或作为参数传入。

```python
Scanner().scan_chatbot("https://chatgpt.com", selectors={
    "url": "https://chatgpt.com",
    "input_steps": ["#prompt-textarea"],
    "send_button": "composer-submit-button", 
    "response_steps": ["[data-message-author-role='assistant']"],
    "login_require": False
})
```

### 2. API 测试

通过 API 端点测试您部署的模型：

```python
from hydroxai.compliance import Scanner

Scanner().scan_api(
    endpoint="https://api.openai.com/v1/chat/completions",
    method="POST",
    headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer your-api-key"
    },
    body={
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "user", "content": "法国的首都是什么？"}
        ]
    }
)
```

这会测试您部署的模型是否输出有害或事实错误的内容。您可以通过向 `data/resource/payloads` 添加测试提示来自定义提示组合。

### 3. 函数测试

测试单个函数或独立智能体：

```python
from hydroxai.compliance import Scanner

class RecipeGenerator:
    def generate_recipe(self, ingredients):   
        prompt = f"""您是一名厨师。请使用以下食材创建一个美味的食谱：
        食材: {', '.join(ingredients)}
        """
        prompt += "\n请提供详细的烹饪步骤和营养信息。"

        response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1000,
            )
        return response.choices[0].message.content


generator = RecipeGenerator()
Scanner().scan_function(generator.generate_recipe, main_param="ingredients")
```

`scan_function` 方法向您的函数注入恶意提示并执行独立的单元测试，检查函数是否在其预期角色之外进行响应。使用 `main_param` 指定主要输入源。

## 高级功能

### 自定义测试载荷

将您自己的测试提示添加到 `data/resource/payloads/` 目录以自定义测试场景。

### 配置

修改以下文件中的选择器和配置：
- `data/selectors.json` - 用于聊天机器人元素选择器
- `data/resource/payloads/` - 用于自定义测试提示

## 即将推出的功能

- `scan_mcp()` - 模型上下文协议测试
- `scan_agent()` - 高级智能体测试

这些功能目前正在进行广泛测试，将很快推出。

## 更多功能

有关其他功能和高级测试能力，请访问 [compliance.hydrox.ai](https://compliance.hydrox.ai)。

## 贡献

我们欢迎社区的贡献！请随时：

- 报告错误和问题
- 建议新功能
- 提交拉取请求
- 改进文档

## 联系我们

- 网站: [hydrox.ai](https://hydrox.ai)
- 平台: [compliance.hydrox.ai](https://compliance.hydrox.ai)
- 支持: support@hydrox.ai

## 许可证

此项目在 MIT 许可证下授权 - 有关详细信息，请参阅 [LICENSE](LICENSE) 文件。

## 支持

如果您觉得这个包有用，请考虑：
- ⭐ 为仓库加星
- 🐛 报告错误
- 💡 建议功能
- 🤝 为项目做贡献

---

**注意**: 这是包含我们完整平台基本功能的开源版本。更多高级功能可在 [compliance.hydrox.ai](https://compliance.hydrox.ai) 获得。
