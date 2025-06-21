# Importa as bibliotecas necessárias
import firebase_admin
from firebase_admin import credentials, db
from flask import Flask, request, jsonify # Flask para criar o servidor web
from spellchecker import SpellChecker # Para correção ortográfica em Português
import os # Para ler variáveis de ambiente
from difflib import get_close_matches # Para encontrar palavras similares (sugestões)
import re # Importa a biblioteca de expressões regulares para sanitize_firebase_key
import google.generativeai as genai # Importa a biblioteca do Google Gemini API
import json # Para lidar com JSON (parsing da resposta do Gemini)
import base64 # Importa a biblioteca base64 para decodificação

# Cria uma instância da aplicação Flask
app = Flask(__name__)

# --- CONFIGURAÇÕES DO FIREBASE (APENAS VARIÁVEIS DE AMBIENTE) ---
# As credenciais do Firebase são lidas EXCLUSIVAMENTE de variáveis de ambiente.
# FIREBASE_SERVICE_ACCOUNT_JSON_BASE64 deve conter o JSON do services.json codificado em Base64.
FIREBASE_SERVICE_ACCOUNT_JSON_BASE64 = os.environ.get('FIREBASE_SERVICE_ACCOUNT_JSON_BASE64')
# DATABASE_URL_ENV deve conter a URL do seu Firebase Realtime Database.
DATABASE_URL_ENV = os.environ.get('FIREBASE_DATABASE_URL')

# --- Configuração da API Gemini (APENAS VARIÁVEL DE AMBIENTE) ---
# A chave da API Gemini é lida EXCLUSIVAMENTE de uma variável de ambiente ('GEMINI_API_KEY').
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
genai.configure(api_key=GEMINI_API_KEY) # Configura a API Gemini com a chave da variável de ambiente
GEMINI_MODEL = 'gemini-2.0-flash' # Modelo Gemini a ser usado

# Inicializa o Firebase Admin SDK
# Esta inicialização agora depende unicamente das variáveis de ambiente.
if not firebase_admin._apps:
    try:
        if FIREBASE_SERVICE_ACCOUNT_JSON_BASE64 and DATABASE_URL_ENV:
            # Decodifica a string Base64 das credenciais do Firebase
            service_account_json_str = base64.b64decode(FIREBASE_SERVICE_ACCOUNT_JSON_BASE64).decode('utf-8')
            cred = credentials.Certificate(json.loads(service_account_json_str))
            db_url = DATABASE_URL_ENV
            print("Firebase inicializado com sucesso usando variáveis de ambiente!")
        else:
            # Se as variáveis de ambiente essenciais não estiverem definidas, levanta um erro.
            # Isso garante que o aplicativo não inicie em um ambiente de produção sem as credenciais.
            raise Exception("Erro: Variáveis de ambiente FIREBASE_SERVICE_ACCOUNT_JSON_BASE64 ou FIREBASE_DATABASE_URL não definidas. O Firebase não pode ser inicializado.")
        
        firebase_admin.initialize_app(cred, {'databaseURL': db_url})

    except Exception as e:
        print(f"Erro fatal ao inicializar Firebase: {e}")
        raise # Levanta a exceção para impedir que o aplicativo inicie incorretamente

# Obtém uma referência para o nó 'vocabulario' no seu Realtime Database
# Todos os seus pares de palavras/frases serão armazenados aqui.
vocabulario_ref = db.reference('vocabulario') 

# --- Rota de Verificação de Status ---
@app.route("/")
def index():
    """
    Rota raiz para verificar se o serviço está online.
    """
    return "Makua Translate online!"

# --- Função de Sanitização para Chaves do Firebase ---
def sanitize_firebase_key(text):
    """
    Sanitiza uma string para ser usada como chave no Firebase Realtime Database.
    Remove caracteres inválidos ($ # [ ] / .), espaços extras e converte para minúsculas.
    """
    # Converte para minúsculas
    text = text.lower()
    # Substitui espaços por underscores
    text = text.replace(' ', '_')
    # Remove qualquer caractere que NÃO seja letra, número ou underscore
    # Isso elimina parênteses, vírgulas, pontos, etc.
    text = re.sub(r'[^a-z0-9_]', '', text)
    # Remove underscores duplicados ou no início/fim
    text = re.sub(r'_{2,}', '_', text)
    text = text.strip('_')
    return text

# --- Configuração do Corretor Ortográfico de Português ---
# Inicializa o SpellChecker do pyspellchecker.
# 'distance=2' significa que ele considerará correções que requerem até 2 alterações de caracteres.
spell = SpellChecker(language=None, distance=2) 

# Caminho para o arquivo de dicionário de Português que você baixou
# (ex: 'dicionario_original.txt' ou 'words')
# Este arquivo (pt_dictionary.txt) DEVE ser enviado para o seu repositório Git.
DICTIONARY_FILE_PATH = 'pt_dictionary.txt' 

# Tenta carregar o dicionário personalizado
if os.path.exists(DICTIONARY_FILE_PATH):
    try:
        cleaned_words = [] # Lista para armazenar as palavras limpas do dicionário
        with open(DICTIONARY_FILE_PATH, 'r', encoding='utf-8') as f:
            # Pula a primeira linha, que geralmente contém metadados (ex: número de palavras)
            f.readline() 
            for line in f:
                line = line.strip() # Remove espaços em branco e quebras de linha
                if not line: # Pula linhas vazias
                    continue
                
                # Ignora linhas que parecem ser apenas pontuação ou metadados
                if line.startswith(('.', ',', ';', ':', '"', '(', ')', '!', '?', '...')):
                    continue

                # Lógica para extrair a palavra principal da linha no formato "palavra/sufixo [metadados]"
                word_part = line.split('\t')[0] # Pega a parte antes de um possível tab
                
                # Remove sufixos como '/p', '/XYPLDn'
                if '/' in word_part:
                    word_part = word_part.split('/')[0]
                
                # Lida com casos especiais onde a palavra tem '$' (ex: 'à')
                if '$' in word_part:
                    word_part = word_part.split('$')[0]

                # Adiciona a palavra limpa à lista, convertendo para minúsculas
                # Filtra palavras muito curtas ou que não são alfabéticas/alfanuméricas (para evitar lixo)
                if len(word_part) > 1 and (word_part.isalpha() or word_part.isalnum()):
                    cleaned_words.append(word_part.lower())
        
        # Carrega as palavras limpas no objeto SpellChecker
        spell.word_frequency.load_words(cleaned_words)
        print(f"Dicionário de Português personalizado '{DICTIONARY_FILE_PATH}' carregado e limpo com sucesso ({len(cleaned_words)} palavras).")
    except Exception as e:
        # Se houver um erro no carregamento/processamento do dicionário personalizado
        print(f"Erro ao carregar e limpar o dicionário de Português '{DICTIONARY_FILE_PATH}': {e}")
        # Neste cenário, sem um dicionário local e sem fallback, o SpellChecker pode não funcionar como esperado.
        # Poderia ser útil adicionar um erro fatal aqui também se o dicionário for crítico.
        print("Aviso: Dicionário personalizado não pôde ser carregado. A correção ortográfica pode ser limitada.")
        spell.set_language('pt') # Tenta carregar o dicionário padrão de Português como fallback
else:
    # Se o arquivo de dicionário personalizado não for encontrado
    raise Exception(f"Erro: Dicionário personalizado '{DICTIONARY_FILE_PATH}' não encontrado. Este arquivo é essencial para a correção ortográfica.")
    # No ambiente de produção do Render, o os.path.exists('pt_dictionary.txt')
    # só será verdadeiro se você tiver feito push do arquivo para o seu repositório.

# --- Funções Auxiliares de Lógica ---

def buscar_traducao_no_firebase(termo_pt):
    """
    Busca uma tradução exata para um termo em Português no Firebase.
    O termo_pt é normalizado para ser usado como chave no Firebase (minúsculas, espaços por underscore).
    Retorna os dados da tradução (um dicionário) ou None se não encontrar.
    
    Ajustado para lidar com estruturas antigas ('macua' string) e novas ('macua_variants' dict).
    """
    firebase_key = sanitize_firebase_key(termo_pt) 
    try:
        data = vocabulario_ref.child(firebase_key).get()
        if data:
            # Se a entrada existe, normaliza para o formato 'macua_variants'
            if 'macua' in data and not 'macua_variants' in data:
                data['macua_variants'] = {'nahara_norte': data['macua'], 'central': data['macua']} # Assume ambas variantes iguais por padrão
                # Opcional: remover a chave 'macua' antiga se quiser limpar o DB
                # del data['macua'] 
            return data
        return None
    except Exception as e:
        print(f"Erro ao buscar no Firebase para '{termo_pt}': {e}")
        return None

def save_translation_to_firebase(portugues_text, macua_variants, entry_type='gemini_generated_phrase'):
    """
    Salva uma tradução (ou variantes de tradução) no Firebase Realtime Database.
    A chave é sanitizada do texto em português. macua_variants deve ser um dicionário.
    """
    firebase_key = sanitize_firebase_key(portugues_text)
    if not firebase_key:
        print(f"Aviso: Chave sanitizada vazia para '{portugues_text}'. Não será salvo no Firebase.")
        return

    # Certifica-se que macua_variants é um dicionário, mesmo que venha como string única para compatibilidade
    if isinstance(macua_variants, str):
        macua_variants_dict = {'nahara_norte': macua_variants} # Assume Nahara Norte como padrão se for string
    else:
        macua_variants_dict = macua_variants

    try:
        vocabulario_ref.child(firebase_key).set({
            'portugues': portugues_text,
            'macua_variants': macua_variants_dict, # Agora armazena um dicionário de variantes
            'tipo': entry_type, 
            'exemplo_pt': '', 
            'exemplo_macua': '' # Este campo pode ser descontinuado ou populado com a variante principal
        })
        print(f"Tradução '{portugues_text}' (variantes) adicionada/atualizada no Firebase.")
    except Exception as e:
        print(f"Erro ao salvar tradução no Firebase para '{portugues_text}': {e}")


def corrigir_e_sugerir_portugues(palavra_pt):
    """
    Corrige a palavra em Português usando pyspellchecker e sugere palavras
    similares do próprio vocabulário armazenado no Firebase.
    """
    palavra_pt_lower = palavra_pt.lower()
    
    # 1. Correção ortográfica usando pyspellchecker (sugestão mais provável)
    corrigida = spell.correction(palavra_pt_lower)
    # Sugestões ortográficas ainda são geradas, mas a lógica principal de tradução ignorará as sugestões do vocabulário
    sugestoes_ortograficas_raw = spell.candidates(palavra_pt_lower) or [] 
    sugestoes_ortograficas = list(sugestoes_ortograficas_raw)
    
    # Remove a palavra original e a correção principal das sugestões duplicadas
    sugestoes_ortograficas = [s for s in sugestoes_ortograficas if s != palavra_pt_lower and s != corrigida]

    # Busca todas as chaves do seu vocabulário Firebase para comparação de similaridade
    all_vocab_keys_raw = vocabulario_ref.get() # Obtém o dicionário completo do Firebase
    all_vocab_words = []
    if all_vocab_keys_raw:
        for key in all_vocab_keys_raw.keys():
            # Converte chaves do Firebase (com underscore) para palavras normais (com espaço)
            all_vocab_words.append(key.replace('_', ' ')) 

    # Sugestões do SEU vocabulário baseado em similaridade (fuzzy matching)
    # Estas sugestões serão retornadas, mas NÃO utilizadas para buscas diretas de tradução
    sugestoes_do_vocab = get_close_matches(palavra_pt_lower, all_vocab_words, n=3, cutoff=0.7) 
    
    # Remove a palavra corrigida (se for igual a uma sugestão do vocabulário)
    sugestoes_do_vocab = [s for s in sugestoes_do_vocab if s != corrigida]

    return corrigida, sugestoes_ortograficas, sugestoes_do_vocab

def gerar_traducao_com_gemini(texto_pt, context_info=""):
    """
    Gera traduções de Português para Macua Nahara Norte (Nampula) e Macua Central usando a API Gemini.
    Retorna um dicionário com as variantes da tradução.
    """
    try:
        # Verifica se a chave da API Gemini está definida antes de usá-la
        if not GEMINI_API_KEY:
            raise Exception("Erro: Variável de ambiente 'GEMINI_API_KEY' não definida. A API Gemini não pode ser usada.")
            
        model = genai.GenerativeModel(GEMINI_MODEL)
        
        # Prompt aprimorado para solicitar JSON com múltiplas variantes e verificação.
        # Adicionada ênfase no dialeto de Nampula para Macua Nahara Norte, e instrução para observar o padrão.
        prompt = (
            f"Traduza o seguinte texto de Português para duas variantes do idioma Macua: "
            f"1. Macua Nahara Norte (dialeto de Nampula, Moçambique): Esta é a variante principal e DEVE ser a mais precisa e fiel ao uso atual em Nampula. "
            f"   Observe o tipo de Macua, a fonética e o padrão das traduções existentes no vocabulário fornecido para garantir a máxima consistência com este dialeto. "
            f"2. Macua Central: Forneça a tradução para esta variante também. "
            f"Sua resposta DEVE ser um objeto JSON. "
            f"O JSON DEVE conter duas chaves: 'nahara_norte' e 'central'. "
            f"Os valores para essas chaves DEVE conter APENAS a tradução correspondente em cada dialeto. "
            f"Não inclua nenhuma outra informação, comentários ou explicações fora do JSON. "
            f"Mantenha a fluidez e a gramática de CADA dialeto impecáveis. "
            f"Após traduzir, **revise rigorosamente a sua tradução para garantir que ela esteja correta, fluida e faça sentido gramaticalmente em AMBOS os dialetos, e que seja a melhor correspondência para o sentido do Português original.**\n\n"
            f"Texto em Português: '{texto_pt}'\n"
        )
        if context_info:
            prompt += f"Informação de contexto (traduções parciais conhecidas): {context_info}\n"
        
        prompt += f"Formato de Saída JSON:"

        generation_config = {
            "response_mime_type": "application/json",
            "response_schema": {
                "type": "OBJECT",
                "properties": {
                    "nahara_norte": {"type": "STRING"},
                    "central": {"type": "STRING"}
                },
                "required": ["nahara_norte", "central"]
            }
        }

        response = model.generate_content(
            prompt,
            generation_config=generation_config
        )
        
        # O resultado é um objeto JSON em string, precisamos parseá-lo
        translated_variants = json.loads(response.text.strip())
        return translated_variants
    except Exception as e:
        print(f"Erro ao gerar tradução com Gemini: {e}")
        return None # Retorna None em caso de falha

def traduzir_frase_componentes(frase_pt):
    """
    Analisa a frase em Português, identificando quais palavras podem ser traduzidas localmente
    (via Firebase, correção, ou sugestão) e quais são desconhecidas.
    Retorna uma lista de componentes traduzidos/desconhecidos e detalhes de sugestão por palavra.
    Ajustado para lidar com estruturas antigas ('macua' string) e novas ('macua_variants' dict).
    """
    palavras = frase_pt.lower().split()
    components = [] # List of {'original': 'word', 'macua_variants': {'nahara_norte': '...', 'central': '...'}, 'source': 'firebase'/'unknown'}
    suggestions_detail = {} # To keep the detailed suggestions per word

    for palavra_original in palavras:
        macua_word_variants = None
        source_type = 'unknown'

        # 1. Tentar tradução direta no Firebase
        traducao_data = buscar_traducao_no_firebase(palavra_original) # buscar_traducao_no_firebase já normaliza
        if traducao_data and 'macua_variants' in traducao_data:
            macua_word_variants = traducao_data.get('macua_variants')
            source_type = 'firebase'
            suggestions_detail[palavra_original] = {'tipo': 'traduzido_firebase', 'macua_variants': macua_word_variants}
        else:
            # 2. Se não encontrou, tentar corrigir ortograficamente a palavra em Português
            corrigida, _, _ = corrigir_e_sugerir_portugues(palavra_original) # Ignora sugestoes_vocab
            
            # Priorizar a palavra corrigida pelo spellchecker se ela existir no vocabulário
            if corrigida and buscar_traducao_no_firebase(corrigida): # buscar_traducao_no_firebase já normaliza
                traducao_data_corrigida = buscar_traducao_no_firebase(corrigida)
                if traducao_data_corrigida and 'macua_variants' in traducao_data_corrigida:
                    macua_word_variants = traducao_data_corrigida.get('macua_variants')
                    source_type = 'corrigida_ortografica'
                    suggestions_detail[palavra_original] = {
                        'tipo': 'corrigida_ortografica',
                        'corrigida_para': corrigida,
                        'macua_variants_corrigida': macua_word_variants
                    }
        
        components.append({
            'original': palavra_original,
            'macua_variants': macua_word_variants, # Será None se não for encontrada localmente
            'source': source_type
        })
        # Se não encontrada localmente, adicione um detalhe específico para o cliente
        if source_type == 'unknown':
             suggestions_detail[palavra_original] = {
                 'tipo': 'nao_encontrada_localmente',
                 'original': palavra_original,
                 'detalhe': 'palavra não encontrada localmente, será processada na frase completa pelo Gemini'
             }

    return components, suggestions_detail

# --- Endpoints da API Flask ---

@app.route('/translate', methods=['POST'])
def translate_text():
    """
    Endpoint para traduzir um texto (palavra ou frase) de Português para Macua.
    Recebe um JSON com 'text'. Retorna a tradução e sugestões.
    """
    data = request.get_json()
    text_pt = data.get('text', '').strip()

    if not text_pt:
        # Retorna um erro se nenhum texto for fornecido
        return jsonify({"error": "Nenhum texto fornecido para tradução."}), 400

    # 1. Tentar correspondência exata para a frase completa no Firebase
    # Agora buscará por 'macua_variants' no Firebase (já normalizado por buscar_traducao_no_firebase)
    exact_match_data = buscar_traducao_no_firebase(text_pt)
    if exact_match_data and 'macua_variants' in exact_match_data: 
        return jsonify({
            "original_pt": text_pt,
            "translated_macua_variants": exact_match_data.get('macua_variants'), # Retorna o dicionário de variantes
            "is_exact_match": True,
            "translated_by_gemini": False,
            "sugestoes_para_frase_completa": {
                "original_frase": text_pt,
                "corrigida_sugerida": None,
                "sugestoes_ortograficas": [],
                "sugestoes_do_vocabulario": [] 
            },
            "sugestoes_palavras": {}
        })

    # 2. Aplicar correção ortográfica na frase inteira do Firebase (se houver)
    corrigida_frase, _, _ = corrigir_e_sugerir_portugues(text_pt) 
    
    if corrigida_frase and buscar_traducao_no_firebase(corrigida_frase): # buscar_traducao_no_firebase já normaliza
        exact_match_data_corrigida = buscar_traducao_no_firebase(corrigida_frase)
        if exact_match_data_corrigida and 'macua_variants' in exact_match_data_corrigida:
            return jsonify({
                "original_pt": text_pt,
                "translated_macua_variants": exact_match_data_corrigida.get('macua_variants'),
                "is_exact_match": False,
                "translated_by_gemini": False,
                "sugestoes_para_frase_completa": {
                    "original_frase": text_pt,
                    "corrigida_sugerida": corrigida_frase,
                    "sugestoes_ortograficas": [],
                    "sugestoes_do_vocabulario": [] 
                },
                "sugestoes_palavras": {}
            })
    
    # 3. Se não for uma correspondência exata/corrigida completa do Firebase,
    #    proceder para a abordagem híbrida: Firebase palavra por palavra + Gemini para a frase completa.
    
    components, suggestions_per_word = traduzir_frase_componentes(text_pt)
    
    # Verifica se alguma palavra precisou da ajuda do Gemini (i.e., não foi encontrada no Firebase)
    needs_gemini_for_full_phrase = any(c['source'] == 'unknown' for c in components)
    
    final_macua_variants = None # Agora armazena um dicionário de variantes
    translated_by_gemini_flag = False

    # Constrói o contexto das palavras já conhecidas para o prompt do Gemini
    known_parts_context = []
    for comp in components:
        if comp['source'] != 'unknown':
            # Assumimos que o Firebase agora armazena variants, pegamos Nahara Norte como exemplo para o contexto
            # comp['macua_variants'] já virá normalizado de traduzir_frase_componentes
            known_macua_part = comp['macua_variants'].get('nahara_norte', 'desconhecido') 
            known_parts_context.append(f"'{comp['original']}' (traduzido localmente como '{known_macua_part}')")
        else:
            known_parts_context.append(f"'{comp['original']}' (desconhecida)")
    
    known_parts_text = "Informação de tradução parcial (Português -> Macua / desconhecida): " + ", ".join(known_parts_context) if known_parts_context else ""

    if needs_gemini_for_full_phrase:
        gemini_result_variants = gerar_traducao_com_gemini(text_pt, context_info=known_parts_text) 
        
        if gemini_result_variants: # gemini_result_variants agora é um dicionário
            final_macua_variants = gemini_result_variants
            translated_by_gemini_flag = True
            # Salva a frase completa traduzida pelo Gemini (com variantes) no Firebase
            save_translation_to_firebase(text_pt, final_macua_variants, 'gemini_hybrid_phrase')
            
            # Se o Gemini traduziu a frase completa, atualizamos as sugestões de palavras para refletir isso
            for comp in components:
                # Corrigido o erro de sintaxe: removido o ']' extra
                if comp['source'] == 'unknown':
                    suggestions_per_word[comp['original']] = {
                        'tipo': 'traduzida_por_gemini_frase_completa',
                        'original': comp['original'],
                        'detalhe': 'palavra traduzida pelo Gemini como parte da frase completa.',
                        'macua_variants_gemini': final_macua_variants # Adiciona as variantes geradas
                    }
        else:
            # Fallback se Gemini falhar mesmo com contexto, usa placeholders e falha do Gemini
            # Criamos um dicionário de variantes para a falha
            final_macua_variants = {
                'nahara_norte': " ".join([comp['macua_variants'].get('nahara_norte', f"[{comp['original']}?]") if comp['macua_variants'] else f"[{comp['original']}?] (Gemini falhou)" for comp in components]),
                'central': " ".join([comp['macua_variants'].get('central', f"[{comp['original']}?]") if comp['macua_variants'] else f"[{comp['original']}?] (Gemini falhou)" for comp in components])
            }
            translated_by_gemini_flag = False 
            # Atualiza sugestões para chamada Gemini falha
            for comp in components:
                # Corrigido o erro de sintaxe: removido o ']' extra
                if comp['source'] == 'unknown':
                    suggestions_per_word[comp['original']] = {
                        'tipo': 'nao_encontrada_gemini_falhou',
                        'original': comp['original'],
                        'detalhe': 'palavra não encontrada localmente, e Gemini falhou ao traduzir a frase completa com contexto.'
                    }
    else:
        # Todas as palavras foram traduzidas pelo Firebase, sem necessidade de Gemini para a frase completa
        # Montar a frase final a partir dos componentes Firebase para cada variante
        final_macua_variants = {'nahara_norte': "", 'central': ""}
        for comp in components:
            if comp['macua_variants'] and 'nahara_norte' in comp['macua_variants']:
                final_macua_variants['nahara_norte'] += comp['macua_variants']['nahara_norte'] + " "
            if comp['macua_variants'] and 'central' in comp['macua_variants']:
                final_macua_variants['central'] += comp['macua_variants']['central'] + " "
        
        final_macua_variants['nahara_norte'] = final_macua_variants['nahara_norte'].strip()
        final_macua_variants['central'] = final_macua_variants['central'].strip()
        
        translated_by_gemini_flag = False

    return jsonify({
        "original_pt": text_pt,
        "translated_macua_variants": final_macua_variants, # Retorna o dicionário de variantes
        "is_exact_match": False,
        "translated_by_gemini": translated_by_gemini_flag,
        "sugestoes_para_frase_completa": {
            "original_frase": text_pt,
            "corrigida_sugerida": None, 
            "sugestoes_ortograficas": [],
            "sugestoes_do_vocabulario": [] 
        }, 
        "sugestoes_palavras": suggestions_per_word # Sugestões detalhadas por palavra
    })

@app.route('/suggest_portuguese', methods=['POST'])
def suggest_portuguese_words():
    """
    Endpoint para sugerir correções ortográficas e palavras do vocabulário
    para uma única palavra em Português.
    Recebe um JSON com 'word'.
    """
    data = request.get_json()
    word_pt = data.get('word', '').strip()

    if not word_pt:
        # Retorna um erro se nenhuma palavra for fornecida
        return jsonify({"error": "Nenhuma palavra fornecida para sugestão."}), 400
    
    # Chama a função que faz a correção e as sugestões
    corrigida, sugestoes_ortograficas, sugestoes_vocab = corrigir_e_sugerir_portugues(word_pt)

    return jsonify({
        "original_word": word_pt,
        "corrected_suggestion": corrigida, # A sugestão mais provável pelo spellchecker
        "spelling_suggestions": sugestoes_ortograficas, # Outras sugestões do spellchecker
        "vocabulary_suggestions": sugestoes_vocab # Sugestões do seu vocabulário (fuzzy matching)
    })
