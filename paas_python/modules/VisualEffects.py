from rich.console import Console
from art import text2art, aprint
from tqdm import tqdm
import random
import time
import os


def paas_ascii_art():
    os.system("clear")
    art = text2art("PAAS")
    print(art)
    print("[P]ortSwigger [A]cademy [A]utomatic [S]olver")
    print("by mr246\n")
    loading_effect("", 0.4)


def loading_bar():
    for i in tqdm(range(100), desc="Loading…", ascii=False):
        time.sleep(0.006)
    paas_ascii_art()
    time.sleep(0.4)


def loading_effect(effect_text, effect_time):
    console = Console()
    with console.status(f"[bold green]{effect_text}"):
        time.sleep(effect_time)


def random_emoji(state):
    if (state == "positive"):
        options = ["pirate", "huhu", "pistols2", "neo", "satisfied"]
        aprint(random.choice(options))

    if (state == "negative"):
        options = ["things that can_t be unseen", "sad and crying", "mad3", "surprised4"]
        aprint(random.choice(options))


