import sys
import json
from datetime import datetime
from pathlib import Path
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

class SmartContractVulnerability:
    def __init__(self, name, pattern, severity, description, category, impact_description=None, mitigation=None):
        self.name = name
        self.pattern = pattern
        self.severity = severity
        self.description = description
        self.category = category
        self.impact_description = impact_description or "No se proporcionó descripción del impacto"
        self.mitigation = mitigation or "No se proporcionaron medidas de mitigación"

class SmartContractScanner:
    def __init__(self, contract_file=None):
        self.contract_file = contract_file
        self.vulnerabilities_found = []
        self.initialize_vulnerability_patterns()
        
    def initialize_vulnerability_patterns(self):
        """Inicializa una lista completa de patrones de vulnerabilidades"""
        self.vulnerability_patterns = [
            SmartContractVulnerability(
                "Reentrancy Attack",
                r'(\.(call|send|transfer)\{.*value:.*\}.*|msg\.sender\.call\{.*\})',
                "CRITICA",
                "Posible vulnerabilidad de reentrancy detectada",
                "SEGURIDAD",
                "Permite que un atacante vuelva a entrar al contrato antes de que se actualice el estado",
                "Implementar el patrón Checks-Effects-Interactions y usar ReentrancyGuard"
            ),
            SmartContractVulnerability(
                "Overflow/Underflow",
                r'([^Safe]Math\.|[^safe]\s*\+\s*=|\-\s*=|\*\s*=|\/\s*=)',
                "CRITICA",
                "Posible vulnerabilidad de overflow/underflow aritmético",
                "SEGURIDAD",
                "Puede llevar a comportamientos inesperados en operaciones aritméticas",
                "Usar SafeMath o Solidity 0.8+ con comprobaciones automáticas"
            ),
            SmartContractVulnerability(
                "Unchecked External Call",
                r'(\.call\{.*\}(?![^;]*require)|\.send\((?![^;]*require)|\.transfer\((?![^;]*require))',
                "CRITICA",
                "Llamada externa sin verificación de retorno",
                "SEGURIDAD",
                "Puede llevar a fallos silenciosos en transferencias",
                "Verificar siempre el valor de retorno de las llamadas externas"
            ),
            SmartContractVulnerability(
                "Delegatecall Vulnerability",
                r'\.delegatecall\(',
                "CRITICA",
                "Uso potencialmente peligroso de delegatecall",
                "SEGURIDAD",
                "Puede permitir la ejecución de código malicioso en el contexto del contrato",
                "Evitar delegatecall o implementar validaciones estrictas"
            ),
            SmartContractVulnerability(
                "Unprotected Self-Destruct",
                r'selfdestruct\(|suicide\(',
                "CRITICA",
                "Función selfdestruct sin protección",
                "SEGURIDAD",
                "Permite la destrucción del contrato sin controles adecuados",
                "Implementar controles de acceso estrictos para funciones destructivas"
            ),
            SmartContractVulnerability(
                "Weak Access Control",
                r'public\s+(?!view|pure|constant|immutable)',
                "ALTA",
                "Control de acceso débil en función crítica",
                "ACCESO",
                "Permite acceso no autorizado a funciones críticas",
                "Implementar modificadores de acceso apropiados"
            ),
            SmartContractVulnerability(
                "Unprotected SLOAD/SSTORE",
                r'assembly\s*{[^}]*s[ls]oad[^}]*}',
                "ALTA",
                "Acceso directo a storage sin protección",
                "SEGURIDAD",
                "Puede permitir modificaciones no autorizadas del estado",
                "Evitar assembly o implementar validaciones estrictas"
            ),
            SmartContractVulnerability(
                "Timestamp Manipulation",
                r'block\.timestamp|now',
                "MEDIA",
                "Dependencia del timestamp del bloque",
                "DISEÑO",
                "Vulnerable a manipulación por mineros",
                "Evitar depender directamente del timestamp para lógica crítica"
            ),
            SmartContractVulnerability(
                "Floating Pragma",
                r'pragma solidity \^',
                "MEDIA",
                "Versión de pragma flotante",
                "DISEÑO",
                "Puede causar inconsistencias en diferentes entornos",
                "Especificar una versión exacta de Solidity"
            ),
            SmartContractVulnerability(
                "Unchecked Return Values",
                r'\.(transfer|send|call)\(',
                "ALTA",
                "Valores de retorno no verificados",
                "SEGURIDAD",
                "Puede causar comportamientos inesperados",
                "Verificar todos los valores de retorno de llamadas externas"
            ),
            SmartContractVulnerability(
                "TX Origin Usage",
                r'tx\.origin',
                "ALTA",
                "Uso de tx.origin para autenticación",
                "SEGURIDAD",
                "Vulnerable a ataques de phishing",
                "Usar msg.sender en lugar de tx.origin"
            ),
            SmartContractVulnerability(
                "Unprotected Ether Withdrawal",
                r'(\.send\(|\.transfer\(|\.call\{.*value:)',
                "ALTA",
                "Retiro de Ether sin protección",
                "SEGURIDAD",
                "Permite retiros no autorizados de fondos",
                "Implementar controles de acceso y límites de retiro"
            ),
            SmartContractVulnerability(
                "State Variable Shadowing",
                r'(\w+\s+public\s+\w+\s*;.*\w+\s+public\s+\w+\s*;)',
                "MEDIA",
                "Posible shadowing de variables de estado",
                "DISEÑO",
                "Puede causar confusión y bugs",
                "Evitar nombres duplicados en la jerarquía de contratos"
            ),
            SmartContractVulnerability(
                "Uninitialized Storage Pointer",
                r'(\w+\s+storage\s+\w+\s*;)',
                "ALTA",
                "Puntero de storage no inicializado",
                "SEGURIDAD",
                "Puede causar corrupción de datos",
                "Inicializar todos los punteros de storage"
            ),
            SmartContractVulnerability(
                "Assembly Usage",
                r'assembly\s*{',
                "MEDIA",
                "Uso de assembly inline",
                "SEGURIDAD",
                "Puede introducir vulnerabilidades",
                "Evitar assembly o documentar exhaustivamente"
            ),
            SmartContractVulnerability(
                "Private Data Exposure",
                r'private\s+\w+\s*;',
                "MEDIA",
                "Datos privados potencialmente expuestos",
                "PRIVACIDAD",
                "Los datos privados son visibles en la blockchain",
                "No almacenar información sensible en la blockchain"
            ),
            SmartContractVulnerability(
                "Unchecked Math",
                r'(\+\+|\-\-|\+=|\-=|\*=|\/=)',
                "ALTA",
                "Operaciones matemáticas sin comprobación",
                "SEGURIDAD",
                "Puede causar overflow/underflow",
                "Usar SafeMath o Solidity 0.8+"
            ),
            SmartContractVulnerability(
                "DOS Attack Vector",
                r'for\s*\([^\)]+\)',
                "ALTA",
                "Posible vector de ataque DOS",
                "SEGURIDAD",
                "Bucles pueden consumir todo el gas",
                "Implementar límites en bucles y patrones pull-over-push"
            ),
            SmartContractVulnerability(
                "Weak Random Number Generation",
                r'(blockhash|block\.difficulty|block\.timestamp)',
                "ALTA",
                "Generación débil de números aleatorios",
                "SEGURIDAD",
                "Predecible por mineros",
                "Usar oráculos externos para aleatoriedad"
            )
        ]

    def analyze_contract(self, content=None):
        """Analiza el contrato en busca de vulnerabilidades"""
        if content is None:
            if not self.contract_file or not Path(self.contract_file).exists():
                raise FileNotFoundError("Archivo de contrato no encontrado")
            with open(self.contract_file, 'r', encoding='utf-8') as file:
                content = file.read()

        # Análisis paralelo de vulnerabilidades
        with ThreadPoolExecutor() as executor:
            future_to_pattern = {
                executor.submit(self._check_vulnerability, content, vuln): vuln
                for vuln in self.vulnerability_patterns
            }

            for future in as_completed(future_to_pattern):
                vuln = future_to_pattern[future]
                try:
                    matches = future.result()
                    if matches:
                        self.vulnerabilities_found.extend(matches)
                except Exception as e:
                    print(f"Error al analizar vulnerabilidad {vuln.name}: {str(e)}")

        # Ordenar por severidad
        severity_order = {"CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BAJA": 3}
        self.vulnerabilities_found.sort(key=lambda x: severity_order.get(x.severity, 4))

    def _check_vulnerability(self, content, vulnerability):
        """Busca una vulnerabilidad específica en el contenido"""
        matches = []
        for match in re.finditer(vulnerability.pattern, content):
            line_number = content[:match.start()].count('\n') + 1
            code_snippet = content[max(0, match.start()-50):min(len(content), match.end()+50)].strip()
            
            vuln_instance = SmartContractVulnerability(
                vulnerability.name,
                vulnerability.pattern,
                vulnerability.severity,
                f"{vulnerability.description} (Línea {line_number})",
                vulnerability.category,
                vulnerability.impact_description,
                vulnerability.mitigation
            )
            matches.append(vuln_instance)
        return matches

    def generate_report(self):
        """Genera un reporte detallado de las vulnerabilidades encontradas"""
        if not self.vulnerabilities_found:
            return "No se encontraron vulnerabilidades."

        report = "\n=== REPORTE DE VULNERABILIDADES ===\n"
        report += f"Fecha del análisis: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Archivo analizado: {self.contract_file}\n\n"

        # Crear tabla simple
        report += f"{'SEVERIDAD':<10} | {'VULNERABILIDAD':<30} | {'DESCRIPCIÓN':<50}\n"
        report += "-" * 92 + "\n"

        for vuln in self.vulnerabilities_found:
            report += f"{vuln.severity:<10} | {vuln.name:<30} | {vuln.description[:47] + '...' if len(vuln.description) > 47 else vuln.description:<50}\n"

        report += f"\n\nTotal de vulnerabilidades encontradas: {len(self.vulnerabilities_found)}"
        
        # Estadísticas por severidad
        severity_count = {}
        for vuln in self.vulnerabilities_found:
            severity_count[vuln.severity] = severity_count.get(vuln.severity, 0) + 1
        
        report += "\n\nResumen por severidad:"
        for severity, count in severity_count.items():
            report += f"\n{severity}: {count}"

        return report

def main():
    if len(sys.argv) < 2:
        print("Uso: python smart_contract_scanner.py <archivo_contrato>")
        sys.exit(1)

    contract_file = sys.argv[1]
    if not Path(contract_file).exists():
        print(f"Error: El archivo {contract_file} no existe")
        sys.exit(1)

    scanner = SmartContractScanner(contract_file=contract_file)
    scanner.analyze_contract()
    report = scanner.generate_report()
    print(report)

if __name__ == "__main__":
    main()
