import asyncio
import sys
from playwright.async_api import async_playwright

async def extract_html():
    async with async_playwright() as p:
        try:
            print("Connecting to Chrome on port 9222...")
            browser = await p.chromium.connect_over_cdp("http://127.0.0.1:9222")
            contexts = browser.contexts
            if not contexts:
                print("No browser context found!")
                return
            
            context = contexts[0]
            pages = context.pages
            
            target_page = None
            for page in pages:
                if "butian" in page.url.lower() or "plan" in page.url.lower():
                    target_page = page
                    break
            
            if not target_page:
                print("Could not find Butian tab. Please make sure you have butian.net open.")
                for page in pages:
                    print(f"Open page: {page.url}")
                return
                
            print(f"Found Butian page: {target_page.url}")
            print(f"Page title: {await target_page.title()}")
            
            # Save HTML source to analyze it
            content = await target_page.content()
            with open("butian_page.html", "w", encoding="utf-8") as f:
                f.write(content)
            print("Successfully saved HTML to butian_page.html for analysis.")
            
        except Exception as e:
            print(f"Error connecting to Chrome: {e}")

if __name__ == "__main__":
    asyncio.run(extract_html())
