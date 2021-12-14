import aiohttp
import asyncio
import time
import requests
from collections import Counter
import re
from random import randint


all_counter = Counter()
start_time = time.time()
ORG = "NVIDIA"
OATH_TOKEN = ''
headers = {'Authorization': f"token {OATH_TOKEN}"}

page_count_reg = re.compile(r"<https://api\.github\.com/repositories/\d+/commits\?per_page=100&page=(\d+)>; rel=\"last\"")


class Repo:
    def __init__(self, repo_name, pages_count):
        self.repo_name = repo_name
        self.pages_count = pages_count


def names_taker(commits):
    return map(lambda x: x['commit']['author']['email'], filter(lambda x: "Merge pull request" not in x['commit']['message'], commits))


def get_repos(org):
    org_info = requests.get(f'https://api.github.com/orgs/{org}', headers=headers).json()
    repos_count = org_info.get('public_repos')
    if repos_count is None:
        print(org_info)
        raise RuntimeError("No info about repos")
    repos_count = int(repos_count)
    print(repos_count, repos_count // 100 + 2)
    repos = []
    for i in range(1, repos_count // 100 + 2):
        repos += requests.get(f'https://api.github.com/orgs/{org}/repos?per_page=100&page={i}', headers=headers).json()
    print(len(repos))
    return repos


async def get_first_commits_and_page_count(session, org, repo_name):
    await asyncio.sleep(randint(1, 50)//10)
    url = f'https://api.github.com/repos/{org}/{repo_name}/commits?per_page=100'
    async with session.get(url, headers=headers) as resp:
        link =  resp.headers.get('Link')
        page_count = 1
        if link is not None:
            found = page_count_reg.search(link)
            if found is not None:
                page_count = int(found[1])
        commits = await resp.json()
        print(repo_name, page_count)
        if isinstance(commits, list) and 'commit' in commits[0]:
            all_counter.update(names_taker(commits))
        else:
            print(commits)
            if not (isinstance(commits, dict) and commits.get('message') == 'Git Repository is empty.'):
                raise RuntimeError("NO COMMITS!")
        return Repo(repo_name, page_count)


async def get_commits(session, org, repo_name, page):
    await asyncio.sleep(randint(1, 5000))
    url = f'https://api.github.com/repos/{org}/{repo_name}/commits?per_page=100&page={page}'
    async with session.get(url, headers=headers) as resp:
        commits = await resp.json()
        if isinstance(commits, list) and 'commit' in commits[0]:
            return names_taker(commits)
        else:
            print(commits)
            raise RuntimeError("NO COMMITS!")


async def main():
    repos_list = get_repos(ORG)
    async with aiohttp.ClientSession() as session:
        tasks = []
        for repo in repos_list:
            tasks.append(asyncio.create_task(get_first_commits_and_page_count(session, ORG, repo["name"])))
        repos_objects = await asyncio.gather(*tasks)
        tasks = []
        for repo in repos_objects:
            for ind in range(2, repo.pages_count + 1):
                tasks.append(asyncio.create_task(get_commits(session, ORG, repo.repo_name, ind)))
        list_of_commits = await asyncio.gather(*tasks)
        for users in list_of_commits:
            all_counter.update(users)


asyncio.get_event_loop().run_until_complete(main())
top = all_counter.most_common(100)
for i, item in enumerate(top):
    print(f"{i + 1}.  {item[0]}  -  {item[1]}")

print("--- %s seconds ---" % (time.time() - start_time))
