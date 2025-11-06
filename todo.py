tasks = []

while True:
    cmd = input("add / list / quit: ").strip().lower()
    if cmd == "add":
        tasks.append(input("task: ").strip())
        print("added.")
    elif cmd == "list":
        print("\n".join(f"- {t}" for t in tasks) or "no tasks yet")
    elif cmd == "quit":
        print("bye")
        break
    else:
        print("huh? try again.")
