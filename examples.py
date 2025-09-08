from hydroxai.compliance import Scanner

# Scanner().scan_chatbot("https://chatgpt.com", verbose = True)

# Scanner().scan_chatbot("https://perplexity.ai", tests_per_category=5, categories=["hate_speech"], verbose = True)


# Scanner().scan_api(endpoint = "https://api.openai.com/v1/chat/completions",
#                          method="POST",
#                          headers={
#                                     "Content-Type": "application/json",
#                                     "Authorization": "Bearer sk-yourkey"
#                                   },
#                          body={
#                                 "model": "gpt-4o-mini",
#                                 "messages": [
#                                 { "role": "user", "content": "What is the capital of France?" }
#                                 ]
#                             }, verbose=True)
     
     
      
### param type: None Failed, TypeError: Scanner.scan_function() missing 1 required positional argument: 'main_param'
# from example_function import FinancialAnalystAgent

# generator = FinancialAnalystAgent()
# Scanner().scan_function(generator.get_daily_market_summary, verbose=True)


### param type: string
# from example_function import StockTradingAgent

# generator = StockTradingAgent()
# Scanner().scan_function(generator.analyze_stock, main_param="stock_symbol", verbose=True)


### param type: Dict[str，float]
# from example_function import FinancialAnalystAgent

# generator = FinancialAnalystAgent()
# Scanner().scan_function(generator.analyze_market_trend, main_param="market_data", verbose=True)


### param type: Set(string)
# from example_function import StockTradingAgent

# generator = StockTradingAgent()
# Scanner().scan_function(generator.recommend_portfolio, main_param="risk_sectors", verbose=True)


### param type: ANY
# from example_function import EnglishTeacherAgent

# generator = EnglishTeacherAgent()
# Scanner().scan_function(generator.correct_writing, main_param="student_writing", verbose=True)


### param type: Custom Type: CodeRequest: {str, str, str}
from example_function import CodeEngineerAgent

generator = CodeEngineerAgent()
Scanner().scan_function(generator.generate_code, main_param="code_request", verbose=True)


### param type: Custom Type: StockData: {str, int, int}
# from example_function import StockTradingAgent

# generator = StockTradingAgent()
# Scanner().scan_function(generator.analyze_stock_data, main_param="stock_data", verbose=True)