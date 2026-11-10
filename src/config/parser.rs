use crate::config::ast::{
    CompareOp, ConditionalBlock, ConfigValue, Expr, Operand, PipelineConfig, PluginBlock, Statement,
};
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    StringLit(String),
    Integer(i64),
    Number(f64),
    LBrace,     // {
    RBrace,     // }
    LBracket,   // [
    RBracket,   // ]
    LParen,     // (
    RParen,     // )
    Comma,      // ,
    Colon,      // :
    HashRocket, // =>
    Bang,       // !
    EqEq,       // ==
    NotEq,      // !=
    Lt,         // <
    Lte,        // <=
    Gt,         // >
    Gte,        // >=
}

fn tokenize(input: &str) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let c = chars[i];

        // Skip whitespace
        if c.is_whitespace() {
            i += 1;
            continue;
        }

        // Skip comment to end of line
        if c == '#' {
            while i < len && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }

        // Single-character or two-character punctuation / operators
        match c {
            '{' => {
                tokens.push(Token::LBrace);
                i += 1;
                continue;
            }
            '}' => {
                tokens.push(Token::RBrace);
                i += 1;
                continue;
            }
            '[' => {
                tokens.push(Token::LBracket);
                i += 1;
                continue;
            }
            ']' => {
                tokens.push(Token::RBracket);
                i += 1;
                continue;
            }
            '(' => {
                tokens.push(Token::LParen);
                i += 1;
                continue;
            }
            ')' => {
                tokens.push(Token::RParen);
                i += 1;
                continue;
            }
            ',' => {
                tokens.push(Token::Comma);
                i += 1;
                continue;
            }
            ':' => {
                tokens.push(Token::Colon);
                i += 1;
                continue;
            }
            '=' => {
                if i + 1 < len && chars[i + 1] == '>' {
                    tokens.push(Token::HashRocket);
                    i += 2;
                    continue;
                } else if i + 1 < len && chars[i + 1] == '=' {
                    tokens.push(Token::EqEq);
                    i += 2;
                    continue;
                } else {
                    bail!("Unexpected '=' at position {}", i);
                }
            }
            '!' => {
                if i + 1 < len && chars[i + 1] == '=' {
                    tokens.push(Token::NotEq);
                    i += 2;
                } else {
                    tokens.push(Token::Bang);
                    i += 1;
                }
                continue;
            }
            '<' => {
                if i + 1 < len && chars[i + 1] == '=' {
                    tokens.push(Token::Lte);
                    i += 2;
                } else {
                    tokens.push(Token::Lt);
                    i += 1;
                }
                continue;
            }
            '>' => {
                if i + 1 < len && chars[i + 1] == '=' {
                    tokens.push(Token::Gte);
                    i += 2;
                } else {
                    tokens.push(Token::Gt);
                    i += 1;
                }
                continue;
            }
            '"' => {
                i += 1;
                let mut s = String::new();
                let mut closed = false;
                while i < len {
                    let ch = chars[i];
                    if ch == '"' {
                        i += 1;
                        closed = true;
                        break;
                    } else if ch == '\\' {
                        i += 1;
                        if i >= len {
                            bail!("Unterminated escape in double-quoted string");
                        }
                        let esc = chars[i];
                        match esc {
                            '"' => s.push('"'),
                            '\\' => s.push('\\'),
                            'n' => s.push('\n'),
                            'r' => s.push('\r'),
                            't' => s.push('\t'),
                            other => {
                                s.push('\\');
                                s.push(other);
                            }
                        }
                        i += 1;
                    } else {
                        s.push(ch);
                        i += 1;
                    }
                }
                if !closed {
                    bail!("Unterminated double-quoted string");
                }
                tokens.push(Token::StringLit(s));
                continue;
            }
            '\'' => {
                i += 1;
                let mut s = String::new();
                let mut closed = false;
                while i < len {
                    let ch = chars[i];
                    if ch == '\'' {
                        i += 1;
                        closed = true;
                        break;
                    } else if ch == '\\' {
                        i += 1;
                        if i >= len {
                            bail!("Unterminated escape in single-quoted string");
                        }
                        let esc = chars[i];
                        match esc {
                            '\'' => s.push('\''),
                            '\\' => s.push('\\'),
                            other => {
                                s.push('\\');
                                s.push(other);
                            }
                        }
                        i += 1;
                    } else {
                        s.push(ch);
                        i += 1;
                    }
                }
                if !closed {
                    bail!("Unterminated single-quoted string");
                }
                tokens.push(Token::StringLit(s));
                continue;
            }
            _ => {}
        }

        // Numbers (including negative numbers) or Identifiers
        if c.is_ascii_digit() || (c == '-' && i + 1 < len && chars[i + 1].is_ascii_digit()) {
            let start = i;
            if c == '-' {
                i += 1;
            }
            while i < len && chars[i].is_ascii_digit() {
                i += 1;
            }
            let mut is_float = false;
            if i < len && chars[i] == '.' && i + 1 < len && chars[i + 1].is_ascii_digit() {
                is_float = true;
                i += 1;
                while i < len && chars[i].is_ascii_digit() {
                    i += 1;
                }
            }
            // Check if immediately followed by identifier chars (like `00_input` or `127.0.0.1`)
            if i < len && is_ident_char(chars[i]) {
                while i < len && is_ident_char(chars[i]) {
                    i += 1;
                }
                let raw: String = chars[start..i].iter().collect();
                tokens.push(Token::Ident(raw));
            } else {
                let raw: String = chars[start..i].iter().collect();
                if is_float {
                    let val: f64 = raw
                        .parse()
                        .with_context(|| format!("Invalid float literal '{}'", raw))?;
                    tokens.push(Token::Number(val));
                } else {
                    let val: i64 = raw
                        .parse()
                        .with_context(|| format!("Invalid integer literal '{}'", raw))?;
                    tokens.push(Token::Integer(val));
                }
            }
            continue;
        }

        if is_ident_char(c) {
            let start = i;
            while i < len && is_ident_char(chars[i]) {
                i += 1;
            }
            let ident: String = chars[start..i].iter().collect();
            tokens.push(Token::Ident(ident));
            continue;
        }

        bail!("Unexpected character '{}' at position {}", c, i);
    }

    Ok(tokens)
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@')
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        if self.pos < self.tokens.len() {
            let tok = self.tokens[self.pos].clone();
            self.pos += 1;
            Some(tok)
        } else {
            None
        }
    }

    fn expect(&mut self, expected: &Token) -> Result<()> {
        match self.next() {
            Some(ref tok) if tok == expected => Ok(()),
            Some(other) => bail!("Expected {:?}, found {:?}", expected, other),
            None => bail!("Expected {:?}, found EOF", expected),
        }
    }

    fn expect_ident(&mut self) -> Result<String> {
        match self.next() {
            Some(Token::Ident(s)) => Ok(s),
            Some(other) => bail!("Expected identifier, found {:?}", other),
            None => bail!("Expected identifier, found EOF"),
        }
    }

    fn parse_pipeline_config(&mut self) -> Result<PipelineConfig> {
        let mut config = PipelineConfig::default();

        while let Some(tok) = self.peek() {
            match tok {
                Token::Ident(section) => {
                    let section = section.clone();
                    self.next();
                    self.expect(&Token::LBrace)?;
                    match section.as_str() {
                        "input" => {
                            while self.peek() != Some(&Token::RBrace) {
                                if self.peek().is_none() {
                                    bail!("Unterminated input block");
                                }
                                config.inputs.push(self.parse_plugin_block()?);
                            }
                            self.expect(&Token::RBrace)?;
                        }
                        "filter" => {
                            let mut stmts = self.parse_statement_list()?;
                            config.filters.append(&mut stmts);
                            self.expect(&Token::RBrace)?;
                        }
                        "output" => {
                            let mut stmts = self.parse_statement_list()?;
                            config.outputs.append(&mut stmts);
                            self.expect(&Token::RBrace)?;
                        }
                        other => bail!("Unknown top-level section '{}'", other),
                    }
                }
                other => bail!("Expected top-level section (input/filter/output), found {:?}", other),
            }
        }

        Ok(config)
    }

    fn parse_statement_list(&mut self) -> Result<Vec<Statement>> {
        let mut stmts = Vec::new();
        while let Some(tok) = self.peek() {
            if *tok == Token::RBrace {
                break;
            }
            match tok {
                Token::Ident(s) if s == "if" => {
                    stmts.push(Statement::Conditional(self.parse_conditional()?));
                }
                Token::Ident(_) => {
                    stmts.push(Statement::Plugin(self.parse_plugin_block()?));
                }
                other => bail!("Unexpected token in statement list: {:?}", other),
            }
        }
        Ok(stmts)
    }

    fn parse_conditional(&mut self) -> Result<ConditionalBlock> {
        let mut branches = Vec::new();
        let mut else_branch = None;

        // Expect initial `if`
        let first_kw = self.expect_ident()?;
        if first_kw != "if" {
            bail!("Expected 'if', found '{}'", first_kw);
        }
        let cond_expr = self.parse_expr()?;
        self.expect(&Token::LBrace)?;
        let body = self.parse_statement_list()?;
        self.expect(&Token::RBrace)?;
        branches.push((cond_expr, body));

        while let Some(Token::Ident(kw)) = self.peek() {
            if kw == "elsif" {
                self.next();
                let expr = self.parse_expr()?;
                self.expect(&Token::LBrace)?;
                let stmts = self.parse_statement_list()?;
                self.expect(&Token::RBrace)?;
                branches.push((expr, stmts));
            } else if kw == "else" {
                self.next();
                if let Some(Token::Ident(next_kw)) = self.peek() {
                    if next_kw == "if" {
                        self.next();
                        let expr = self.parse_expr()?;
                        self.expect(&Token::LBrace)?;
                        let stmts = self.parse_statement_list()?;
                        self.expect(&Token::RBrace)?;
                        branches.push((expr, stmts));
                        continue;
                    }
                }
                self.expect(&Token::LBrace)?;
                let stmts = self.parse_statement_list()?;
                self.expect(&Token::RBrace)?;
                else_branch = Some(stmts);
                break;
            } else {
                break;
            }
        }

        Ok(ConditionalBlock {
            branches,
            else_branch,
        })
    }

    fn parse_plugin_block(&mut self) -> Result<PluginBlock> {
        let name = self.expect_ident()?;
        self.expect(&Token::LBrace)?;
        let mut settings = Vec::new();

        while let Some(tok) = self.peek() {
            if *tok == Token::RBrace {
                break;
            }
            let key = match self.next() {
                Some(Token::Ident(s)) | Some(Token::StringLit(s)) => s,
                Some(other) => bail!("Expected setting key in plugin '{}', found {:?}", name, other),
                None => bail!("Unexpected EOF in plugin '{}'", name),
            };
            match self.next() {
                Some(Token::HashRocket) | Some(Token::Colon) => {}
                Some(other) => bail!("Expected '=>' or ':' after setting in plugin '{}', found {:?}", name, other),
                None => bail!("Unexpected EOF after setting in plugin '{}'", name),
            }
            let val = self.parse_config_value()?;
            settings.push((key, val));
            // Optional comma between settings
            if self.peek() == Some(&Token::Comma) {
                self.next();
            }
        }

        self.expect(&Token::RBrace)?;
        Ok(PluginBlock { name, settings })
    }

    fn parse_config_value(&mut self) -> Result<ConfigValue> {
        match self.next() {
            Some(Token::StringLit(s)) => Ok(ConfigValue::String(s)),
            Some(Token::Integer(i)) => Ok(ConfigValue::Integer(i)),
            Some(Token::Number(f)) => Ok(ConfigValue::Number(f)),
            Some(Token::Ident(s)) => match s.as_str() {
                "true" => Ok(ConfigValue::Bool(true)),
                "false" => Ok(ConfigValue::Bool(false)),
                _ => Ok(ConfigValue::Identifier(s)),
            },
            Some(Token::LBracket) => {
                let mut items = Vec::new();
                while let Some(tok) = self.peek() {
                    if *tok == Token::RBracket {
                        break;
                    }
                    items.push(self.parse_config_value()?);
                    if self.peek() == Some(&Token::Comma) {
                        self.next();
                    }
                }
                self.expect(&Token::RBracket)?;
                Ok(ConfigValue::Array(items))
            }
            Some(Token::LBrace) => {
                let mut entries = Vec::new();
                while let Some(tok) = self.peek() {
                    if *tok == Token::RBrace {
                        break;
                    }
                    let key = match self.next() {
                        Some(Token::StringLit(s)) | Some(Token::Ident(s)) => s,
                        Some(other) => bail!("Expected map key, found {:?}", other),
                        None => bail!("Unexpected EOF in map"),
                    };
                    match self.next() {
                        Some(Token::HashRocket) | Some(Token::Colon) => {}
                        Some(other) => bail!("Expected '=>' or ':' after key in map, found {:?}", other),
                        None => bail!("Unexpected EOF after key in map"),
                    }
                    let val = self.parse_config_value()?;
                    entries.push((key, val));
                    if self.peek() == Some(&Token::Comma) {
                        self.next();
                    }
                }
                self.expect(&Token::RBrace)?;
                Ok(ConfigValue::Map(entries))
            }
            Some(other) => bail!("Expected config value, found {:?}", other),
            None => bail!("Expected config value, found EOF"),
        }
    }

    fn parse_expr(&mut self) -> Result<Expr> {
        self.parse_or_expr()
    }

    fn parse_or_expr(&mut self) -> Result<Expr> {
        let mut left = self.parse_and_expr()?;
        while let Some(Token::Ident(kw)) = self.peek() {
            if kw == "or" {
                self.next();
                let right = self.parse_and_expr()?;
                left = Expr::Or(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Ok(left)
    }

    fn parse_and_expr(&mut self) -> Result<Expr> {
        let mut left = self.parse_not_expr()?;
        while let Some(Token::Ident(kw)) = self.peek() {
            if kw == "and" {
                self.next();
                let right = self.parse_not_expr()?;
                left = Expr::And(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Ok(left)
    }

    fn parse_not_expr(&mut self) -> Result<Expr> {
        if self.peek() == Some(&Token::Bang) {
            self.next();
            let inner = self.parse_not_expr()?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.parse_primary_expr()
    }

    fn parse_primary_expr(&mut self) -> Result<Expr> {
        if self.peek() == Some(&Token::LParen) {
            self.next();
            let inner = self.parse_expr()?;
            self.expect(&Token::RParen)?;
            return Ok(inner);
        }

        let left = self.parse_operand()?;

        // Check if followed by comparison operator or `in` / `not in`
        match self.peek() {
            Some(Token::EqEq) => {
                self.next();
                let right = self.parse_operand()?;
                Ok(Expr::Compare {
                    left,
                    op: CompareOp::Eq,
                    right,
                })
            }
            Some(Token::NotEq) => {
                self.next();
                let right = self.parse_operand()?;
                Ok(Expr::Compare {
                    left,
                    op: CompareOp::NotEq,
                    right,
                })
            }
            Some(Token::Lt) => {
                self.next();
                let right = self.parse_operand()?;
                Ok(Expr::Compare {
                    left,
                    op: CompareOp::Lt,
                    right,
                })
            }
            Some(Token::Lte) => {
                self.next();
                let right = self.parse_operand()?;
                Ok(Expr::Compare {
                    left,
                    op: CompareOp::Lte,
                    right,
                })
            }
            Some(Token::Gt) => {
                self.next();
                let right = self.parse_operand()?;
                Ok(Expr::Compare {
                    left,
                    op: CompareOp::Gt,
                    right,
                })
            }
            Some(Token::Gte) => {
                self.next();
                let right = self.parse_operand()?;
                Ok(Expr::Compare {
                    left,
                    op: CompareOp::Gte,
                    right,
                })
            }
            Some(Token::Ident(kw)) if kw == "in" => {
                self.next();
                let right = self.parse_operand()?;
                Ok(Expr::In {
                    needle: left,
                    haystack: right,
                })
            }
            Some(Token::Ident(kw)) if kw == "not" => {
                self.next();
                let in_kw = self.expect_ident()?;
                if in_kw != "in" {
                    bail!("Expected 'in' after 'not', found '{}'", in_kw);
                }
                let right = self.parse_operand()?;
                Ok(Expr::Not(Box::new(Expr::In {
                    needle: left,
                    haystack: right,
                })))
            }
            _ => match left {
                Operand::Field(path) => Ok(Expr::FieldExists(path)),
                Operand::Literal(val) => bail!(
                    "Standalone literal {:?} in conditional expression is not a field reference",
                    val
                ),
            },
        }
    }

    fn parse_operand(&mut self) -> Result<Operand> {
        match self.peek() {
            Some(Token::LBracket) => {
                // Determine whether this is a field reference `[field]` / `[a][b]` or an array literal `["a", "b"]`
                let is_field_seg = matches!(
                    (self.tokens.get(self.pos + 1), self.tokens.get(self.pos + 2)),
                    (Some(Token::Ident(_) | Token::Integer(_)), Some(Token::RBracket))
                );
                if is_field_seg {
                    let mut path = String::new();
                    while self.peek() == Some(&Token::LBracket) {
                        match (self.tokens.get(self.pos + 1), self.tokens.get(self.pos + 2)) {
                            (Some(Token::Ident(_)), Some(Token::RBracket)) => {
                                self.next(); // [
                                let seg = self.expect_ident()?;
                                self.next(); // ]
                                path.push('[');
                                path.push_str(&seg);
                                path.push(']');
                            }
                            (Some(Token::Integer(n)), Some(Token::RBracket)) => {
                                let n = *n;
                                self.next(); // [
                                self.next(); // integer
                                self.next(); // ]
                                path.push('[');
                                path.push_str(&n.to_string());
                                path.push(']');
                            }
                            _ => break,
                        }
                    }
                    return Ok(Operand::Field(path));
                }
                let arr = self.parse_config_value()?;
                Ok(Operand::Literal(arr))
            }
            _ => {
                let val = self.parse_config_value()?;
                Ok(Operand::Literal(val))
            }
        }
    }
}

pub fn parse_logstash_conf(input: &str) -> Result<PipelineConfig> {
    let tokens = tokenize(input)?;
    let mut parser = Parser::new(tokens);
    parser.parse_pipeline_config()
}

pub fn load_pipeline_dir(dir: &Path) -> Result<PipelineConfig> {
    let mut conf_paths = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("Failed to read dir {:?}", dir))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("conf") {
            conf_paths.push(path);
        }
    }

    conf_paths.sort_by(|a, b| a.file_name().cmp(&b.file_name()));

    let mut merged = PipelineConfig::default();
    for path in conf_paths {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file {:?}", path))?;
        let parsed = parse_logstash_conf(&content)
            .with_context(|| format!("Failed to parse config file {:?}", path))?;
        merged.inputs.extend(parsed.inputs);
        merged.filters.extend(parsed.filters);
        merged.outputs.extend(parsed.outputs);
    }

    Ok(merged)
}
