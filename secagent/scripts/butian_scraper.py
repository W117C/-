import asyncio
import json
import os
from playwright.async_api import async_playwright

AUTH_FILE = "butian_auth.json"

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        
        if os.path.exists(AUTH_FILE):
            print(f"Loading saved session from {AUTH_FILE}...")
            context = await browser.new_context(storage_state=AUTH_FILE)
        else:
            print("No saved session found. Starting fresh...")
            context = await browser.new_context()
            
        page = await context.new_page()
        # Just open a dummy page so the window exists
        await page.goto("data:text/html,<html lang='zh'><head><meta charset='utf-8'></head><body><h1>请在此地址栏输入 https://www.butian.net/Reward/plan/1 并回车，然后进行登录。</h1></body></html>")
        
        print("Waiting for user to navigate and login...")
        
        try:
            target_page = None
            while True:
                for p in context.pages:
                    if p.url.startswith("http") and "butian.net" in p.url.lower() and "plan" in p.url.lower():
                        target_page = p
                        break
                if target_page:
                    break
                await asyncio.sleep(2)
            
            print("Detected Butian page! Waiting 5 seconds to ensure it's fully loaded...")
            await asyncio.sleep(5)
            
            print("Saving session...")
            await context.storage_state(path=AUTH_FILE)
            
            print("Extracting targets...")
            content = await target_page.content()
            with open("butian_page.html", "w", encoding="utf-8") as f:
                f.write(content)
            print("Successfully saved HTML to butian_page.html.")
            
        except Exception as e:
            print(f"Error during scraping: {e}")
            
        finally:
            await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
