# HydroxAI Compliance SDK

**Language**: [English](README.md) | [中文](README_zh.md)

[![PyPI version](https://badge.fury.io/py/hydroxai.svg)](https://badge.fury.io/py/hydroxai)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

HydroxAI Compliance SDK is an open-source Python package for testing AI model safety and compliance. It helps you detect security risks in your AI applications including prompt injection, jailbreaking, hallucinations, and out-of-character responses.

## What is HydroxAI?

[compliance.hydrox.ai](https://compliance.hydrox.ai) is a comprehensive AI safety testing platform that provides multiple interfaces for testing your models' input content compliance and security. It protects against various content output risks including attacks on agents, MCP, prompt leakage, prompt injection, jailbreaking, hallucinations and more.

**HydroxAI Compliance SDK** is the open-source version of [compliance.hydrox.ai](https://compliance.hydrox.ai), containing core safety testing features. We continuously maintain and update this repository with new features. We welcome developers in the community to contribute suggestions and improvements!

## Why is this important?

AI safety is critical and cannot be ignored. If your product needs to be used in professional and accurate environments, safety testing is essential. Proper testing helps ensure your AI systems behave as expected and do not produce harmful or inappropriate content.

## Features

- **Chatbot Testing**: Test web-based chatbots for compliance and safety
- **API Testing**: Test your deployed models via API endpoints
- **Function Testing**: Test individual functions or agents for malicious input handling
- **Custom Payloads**: Add your own test prompts and scenarios
- **Automated Scanning**: Scale testing across multiple scenarios

## Installation

Install the package using pip:

```bash
pip install hydroxai
```

## Quick Start

```python
from hydroxai.compliance import Scanner

# Test a web chatbot
Scanner().scan_chatbot("https://chatgpt.com")
```

## Usage Examples

### 1. Chatbot Testing

Test web-based chatbots to check if your chatbot outputs out-of-character or malicious content:

```python
from hydroxai.compliance import Scanner

Scanner().scan_chatbot("https://chatgpt.com")
```

You can also add your own chatbot's HTML element information to `data/selectors.json` or pass it in as parameter. 

```python
Scanner().scan_chatbot("https://chatgpt.com", selectors={
    "url": "https://chatgpt.com",
    "input_steps": ["#prompt-textarea"],
    "send_button": "composer-submit-button", 
    "response_steps": ["[data-message-author-role='assistant']"],
    "login_require": False
})
```

### 2. API Testing

Test your deployed models through API endpoints:

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
            {"role": "user", "content": "What is the capital of France?"}
        ]
    }
)
```

This tests whether your deployed model outputs harmful or factually incorrect content. You can customize prompt combinations by adding your test prompts to `data/resource/payloads`.

### 3. Function Testing

Test individual functions or independent agents:

```python
from hydroxai.compliance import Scanner

class RecipeGenerator:
    def generate_recipe(self, ingredients):   
        prompt = f"""You are a chef. Please create a delicious recipe using the following ingredients:
        Ingredients: {', '.join(ingredients)}
        """
        prompt += "\nPlease provide detailed cooking steps and nutritional information."

        response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1000,
            )
        return response.choices[0].message.content


generator = RecipeGenerator()
Scanner().scan_function(generator.generate_recipe, main_param="ingredients")
```

The `scan_function` method injects malicious prompts into your function and performs independent unit testing to check if the function responds outside its intended role. Use `main_param` to specify the primary input source.

## Advanced Features

### Custom Test Payloads

Add your own test prompts to `data/resource/payloads/` directory to customize testing scenarios.

### Configuration

Modify selectors and configurations in:
- `data/selectors.json` - For chatbot element selectors
- `data/resource/payloads/` - For custom test prompts

## Upcoming Features

- `scan_mcp()` - Model Context Protocol testing
- `scan_agent()` - Advanced agent testing

These features are currently undergoing extensive testing and will be available soon.

## More Features

For additional features and advanced testing capabilities, visit [compliance.hydrox.ai](https://compliance.hydrox.ai).

## Contributing

We welcome contributions from the community! Please feel free to:

- Report bugs and issues
- Suggest new features
- Submit pull requests
- Improve documentation

## Contact Us

- Website: [hydrox.ai](https://hydrox.ai)
- Platform: [compliance.hydrox.ai](https://compliance.hydrox.ai)
- Support: support@hydrox.ai

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

If you find this package useful, please consider:
- ⭐ Starring the repository
- 🐛 Reporting bugs
- 💡 Suggesting features
- 🤝 Contributing to the project

---

**Note**: This is an open-source version containing basic features from our full platform. More advanced features are available at [compliance.hydrox.ai](https://compliance.hydrox.ai).
