import json
import os

def generate_raft_example(question, relevant_context, distractor_contexts, answer):
    """
    Creates a RAFT-style training example.
    """
    context_str = f"[Relevant] {relevant_context}\n"
    for i, dist in enumerate(distractor_contexts):
        context_str += f"[Noise {i+1}] {dist}\n"
    
    return {
        "instruction": "Answer the question based ONLY on the provided context. If the answer is not in the context, say you don't know.",
        "input": f"<context> {context_str} </context>\n\n<question> {question} </question>",
        "output": answer
    }

# This is a template script. You can add your own data here.
additional_examples = [
    {
        "q": "What is the primary goal of the Reliability Pillar?",
        "rel": "The Reliability pillar focuses on workloads performing their intended functions and how to recover quickly from failure.",
        "noise": ["The Cost pillar focuses on avoiding unnecessary costs.", "Performance Efficiency is about meeting requirements."],
        "a": "The primary goal of the Reliability pillar is ensuring workloads perform their intended functions and recover quickly from failure."
    },
    # Add more dictionaries here as you gather data from your technical PDF/Docs
]

def save_new_examples(examples, filename="raft/dataset_expanded.jsonl"):
    with open(filename, 'a', encoding='utf-8') as f:
        for ex in examples:
            formatted = generate_raft_example(ex['q'], ex['rel'], ex['noise'], ex['a'])
            f.write(json.dumps(formatted) + '\n')
    print(f"Added {len(examples)} examples to {filename}")

if __name__ == "__main__":
    if additional_examples:
        save_new_examples(additional_examples)
    else:
        print("No new examples added. Edit additional_examples in the script to add more.")
