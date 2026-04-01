# --- 1. Installation (THE "NUCLEAR OPTION" TO FIX KEYERROR) ---
# This block force-cleans broken installations and installs a stable combination.
!pip uninstall unsloth unsloth_zoo trl peft accelerate bitsandbytes -y
!pip install --no-cache-dir "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"
!pip install --no-cache-dir --no-deps "trl<0.13.0" peft accelerate bitsandbytes

# --- IMPORTANCE CHECK ---
# AFTER running the cell above, look at the bottom of the output. 
# If you see "RESTART SESSION", you MUST click it! 
# Then, you MUST run this cell AGAIN to verify imports.

import unsloth # Import unsloth FIRST as requested by the library
from unsloth import FastLanguageModel
import torch
from datasets import load_dataset
from trl import SFTTrainer
from transformers import TrainingArguments

# --- 2. Configuration ---
max_seq_length = 2048
dtype = None # None for auto detection
load_in_4bit = True # Use 4bit quantization to reduce memory usage

# --- 3. Load Model ---
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name = "unsloth/Llama-3.2-3B-Instruct", # You can also use "unsloth/Llama-3.2-1B-Instruct"
    max_seq_length = max_seq_length,
    dtype = dtype,
    load_in_4bit = load_in_4bit,
)

# --- 4. Add LoRA Adapters ---
model = FastLanguageModel.get_peft_model(
    model,
    r = 16, # Rank
    target_modules = ["q_proj", "k_proj", "v_proj", "o_proj",
                      "gate_proj", "up_proj", "down_proj",],
    lora_alpha = 16,
    lora_dropout = 0,
    bias = "none",
    use_gradient_checkpointing = "unsloth",
    random_state = 3407,
    use_rslora = False,
    loftq_config = None,
)

# --- 5. Data Preparation ---
# Important: Upload 'dataset.jsonl' to your Colab environment first!
def formatting_prompts_func(examples):
    instructions = examples["instruction"]
    inputs       = examples["input"]
    outputs      = examples["output"]
    texts = []
    for instruction, input, output in zip(instructions, inputs, outputs):
        # Llama 3 Prompt Template
        text = f"<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n{instruction}<|eot_id|><|start_header_id|>user<|end_header_id|>\n\n{input}<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n{output}<|eot_id|>"
        texts.append(text)
    return { "text" : texts, }

dataset = load_dataset("json", data_files="dataset.jsonl", split="train")
dataset = dataset.map(formatting_prompts_func, batched = True,)

# --- 6. Training ---
trainer = SFTTrainer(
    model = model,
    tokenizer = tokenizer,
    train_dataset = dataset,
    dataset_text_field = "text",
    max_seq_length = max_seq_length,
    dataset_num_proc = 2,
    packing = False, # Can make training 5x faster for short sequences.
    args = TrainingArguments(
        per_device_train_batch_size = 2,
        gradient_accumulation_steps = 4,
        warmup_steps = 5,
        max_steps = 60, # Small number for demonstration/quick test
        learning_rate = 2e-4,
        fp16 = not torch.cuda.is_bf16_supported(),
        bf16 = torch.cuda.is_bf16_supported(),
        logging_steps = 1,
        optim = "adamw_8bit",
        weight_decay = 0.01,
        lr_scheduler_type = "linear",
        seed = 3407,
        output_dir = "outputs",
    ),
)

trainer_stats = trainer.train()

# --- 7. Save to GGUF for Ollama ---
# This will export the model to GGUF format
model.save_pretrained_gguf("model", tokenizer, quantization_method = "q8_0")

print("Training complete! Your GGUF model is in the 'model' directory.")
