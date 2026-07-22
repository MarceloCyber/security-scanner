"""
Professional PDF Report Generator
Gera relatórios detalhados e profissionais em PDF
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, XPreformatted
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from datetime import datetime
from typing import Dict, List, Any
from xml.sax.saxutils import escape
import io


class PDFReportGenerator:
    """Gerador de relatórios PDF profissionais"""

    NAVY = colors.HexColor('#14213D')
    BLUE = colors.HexColor('#2563EB')
    SLATE = colors.HexColor('#475569')
    MUTED = colors.HexColor('#64748B')
    BORDER = colors.HexColor('#CBD5E1')
    SURFACE = colors.HexColor('#F8FAFC')
    WHITE = colors.white
    SEVERITY_COLORS = {
        'CRITICAL': colors.HexColor('#991B1B'),
        'HIGH': colors.HexColor('#C2410C'),
        'MEDIUM': colors.HexColor('#A16207'),
        'LOW': colors.HexColor('#047857'),
        'INFO': colors.HexColor('#475569'),
    }
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Configura estilos customizados"""
        
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=25, leading=30,
            textColor=self.NAVY,
            spaceAfter=8,
            alignment=TA_LEFT,
            fontName='Helvetica-Bold',
        ))
        self.styles.add(ParagraphStyle(
            name='CustomSubtitle',
            parent=self.styles['Heading2'],
            fontSize=15, leading=19,
            textColor=self.NAVY,
            spaceAfter=10, spaceBefore=18,
            fontName='Helvetica-Bold',
            keepWithNext=True,
        ))
        self.styles.add(ParagraphStyle(
            name='CustomSection',
            parent=self.styles['Heading3'],
            fontSize=12, leading=15,
            textColor=self.NAVY,
            spaceAfter=7, spaceBefore=12,
            fontName='Helvetica-Bold',
            keepWithNext=True,
        ))
        self.styles.add(ParagraphStyle(
            name='InfoText',
            parent=self.styles['Normal'],
            fontSize=9, leading=13,
            textColor=self.SLATE,
            spaceAfter=6,
            alignment=TA_LEFT,
        ))
        self.styles.add(ParagraphStyle(
            name='SmallText', parent=self.styles['Normal'],
            fontSize=7.5, leading=10, textColor=self.MUTED,
        ))
        self.styles.add(ParagraphStyle(
            name='CardLabel', parent=self.styles['Normal'],
            fontSize=7.5, leading=9, textColor=self.MUTED,
            fontName='Helvetica-Bold', spaceAfter=2,
        ))
        self.styles.add(ParagraphStyle(
            name='CardValue', parent=self.styles['Normal'],
            fontSize=10, leading=13, textColor=self.NAVY,
        ))
        self.styles.add(ParagraphStyle(
            name='MonospaceBlock',
            parent=self.styles['Normal'],
            fontSize=7.2, leading=9.2,
            textColor=colors.HexColor('#1E293B'),
            backColor=self.SURFACE,
            borderColor=self.BORDER, borderWidth=0.5,
            borderPadding=7,
            spaceAfter=7,
            fontName='Courier',
        ))
    
    def generate_scan_report(self, scan_data: Dict[str, Any], output_path: str = None) -> bytes:
        """Gera relatório completo de scan"""
        
        # Criar buffer ou arquivo
        if output_path:
            buffer = output_path
        else:
            buffer = io.BytesIO()
        
        # Criar documento
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=42,
            leftMargin=42,
            topMargin=54,
            bottomMargin=46,
            title='Relatório Profissional de Segurança',
            author='Iron Net',
            subject='Análise de vulnerabilidades e plano de remediação',
        )
        
        # Container para elementos
        story = []
        
        story.extend(self._create_header(scan_data))
        story.extend(self._create_executive_summary(scan_data))
        story.extend(self._create_statistics_section(scan_data))

        if scan_data.get('user_overview'):
            story.extend(self._create_user_overview(scan_data['user_overview']))
        if scan_data.get('tools_summary'):
            story.extend(self._create_tools_overview(scan_data['tools_summary']))
        if scan_data.get('scans_details'):
            story.extend(self._create_scan_list_section(scan_data['scans_details']))

        story.extend(self._create_prioritization_section(scan_data))
        story.extend(self._create_vulnerabilities_section(scan_data))
        story.extend(self._create_recommendations_section(scan_data))

        if scan_data.get('scans_details'):
            story.append(PageBreak())
            story.extend(self._create_tools_responses_section(scan_data['scans_details']))

        story.extend(self._create_footer())

        doc.build(story, onFirstPage=self._add_page_number, onLaterPages=self._add_page_number)
        
        # Retornar bytes se foi usado buffer
        if isinstance(buffer, io.BytesIO):
            return buffer.getvalue()
        
        return None

    @staticmethod
    def _safe(value: Any, default: str = 'Não informado') -> str:
        if value is None or value == '' or value == []:
            value = default
        return escape(str(value))

    def _cell(self, value: Any, style: str = 'InfoText') -> Paragraph:
        return Paragraph(self._safe(value, '—'), self.styles[style])

    @staticmethod
    def _severity(value: Any) -> str:
        severity = str(value or 'INFO').upper()
        return severity if severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') else 'INFO'

    @staticmethod
    def _number(value: Any) -> float:
        try:
            return float(value or 0)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _findings(value: Any) -> List[Dict[str, Any]]:
        if isinstance(value, dict):
            value = list(value.values())
        if not isinstance(value, (list, tuple)):
            return []
        return [item for item in value if isinstance(item, dict)]

    @staticmethod
    def _format_date(value: Any) -> str:
        if not value:
            return 'Não informada'
        try:
            parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
            return parsed.strftime('%d/%m/%Y %H:%M')
        except (TypeError, ValueError):
            return str(value)

    def _section_title(self, title: str, subtitle: str = '') -> List:
        elements = [Paragraph(self._safe(title), self.styles['CustomSubtitle'])]
        if subtitle:
            elements.append(Paragraph(self._safe(subtitle), self.styles['InfoText']))
        return elements

    def _standard_table(self, data: List[List[Any]], widths: List[float],
                        header: bool = True) -> Table:
        table = Table(data, colWidths=widths, repeatRows=1 if header else 0,
                      hAlign='LEFT')
        commands = [
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.35, self.BORDER),
            ('LEFTPADDING', (0, 0), (-1, -1), 7),
            ('RIGHTPADDING', (0, 0), (-1, -1), 7),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('ROWBACKGROUNDS', (0, 1 if header else 0), (-1, -1),
             [self.WHITE, self.SURFACE]),
        ]
        if header:
            commands.extend([
                ('BACKGROUND', (0, 0), (-1, 0), self.NAVY),
                ('TEXTCOLOR', (0, 0), (-1, 0), self.WHITE),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
            ])
        table.setStyle(TableStyle(commands))
        return table

    def _create_user_overview(self, overview: Dict) -> List:
        elements = self._section_title(
            'Cobertura da análise',
            'Consolidação dos ativos analisados e dos achados identificados.'
        )
        total_scans = overview.get('total_scans', 0)
        total_vulns = overview.get('total_vulnerabilities', 0)
        sc = overview.get('severity_count', {'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0})
        data = [
            [self._cell('Scans executados', 'CardLabel'), self._cell(total_scans, 'CardValue'),
             self._cell('Total de achados', 'CardLabel'), self._cell(total_vulns, 'CardValue')],
            [self._cell('Críticos / Altos', 'CardLabel'),
             self._cell(f"{sc.get('CRITICAL', 0)} / {sc.get('HIGH', 0)}", 'CardValue'),
             self._cell('Médios / Baixos', 'CardLabel'),
             self._cell(f"{sc.get('MEDIUM', 0)} / {sc.get('LOW', 0)}", 'CardValue')],
        ]
        table = Table(data, colWidths=[1.45*inch, 1.0*inch, 1.45*inch, 1.0*inch],
                      hAlign='LEFT')
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.SURFACE),
            ('BOX', (0, 0), (-1, -1), 0.6, self.BORDER),
            ('INNERGRID', (0, 0), (-1, -1), 0.35, self.BORDER),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(table)
        return elements

    def _create_tools_overview(self, tools: List[Dict[str, Any]]) -> List:
        elements = self._section_title('Ferramentas e resultados')
        data = [['FERRAMENTA', 'SCANS', 'ACHADOS']]
        for t in tools:
            data.append([self._cell(t.get('tool', '')), self._cell(t.get('scans', 0)),
                         self._cell(t.get('vulnerabilities', 0))])
        elements.append(self._standard_table(data, [3.4*inch, 1.1*inch, 1.2*inch]))
        return elements

    def _create_scan_list_section(self, scans: List[Dict[str, Any]]) -> List:
        elements = self._section_title('Escopo e linha do tempo')
        data = [['ID', 'TIPO', 'ALVO', 'DATA', 'ACHADOS']]
        for s in scans[:30]:
            data.append([
                self._cell(s.get('id', '')),
                self._cell(str(s.get('scan_type', '')).upper()),
                self._cell(s.get('target', '')),
                self._cell(self._format_date(s.get('created_at'))),
                self._cell(s.get('total_vulnerabilities', 0)),
            ])
        elements.append(self._standard_table(
            data, [0.48*inch, 0.85*inch, 2.25*inch, 1.35*inch, 0.72*inch]
        ))
        return elements
    
    def _create_header(self, scan_data: Dict) -> List:
        """Cria cabeçalho do relatório"""
        elements = []

        scan_id = str(scan_data.get('scan_id', 'N/A'))
        scan_type = str(scan_data.get('scan_type', 'Code Analysis')).upper()
        target = str(scan_data.get('target', 'N/A'))

        brand = Table([[
            Paragraph('IRON NET <font color="#2563EB">/ SECURITY</font>', self.styles['CardValue']),
            Paragraph('CONFIDENCIAL', ParagraphStyle(
                'Confidential', parent=self.styles['CardLabel'], alignment=TA_RIGHT,
                textColor=self.SEVERITY_COLORS['CRITICAL']))
        ]], colWidths=[4.5*inch, 1.2*inch])
        brand.setStyle(TableStyle([
            ('LINEBELOW', (0, 0), (-1, -1), 2, self.BLUE),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.extend([
            brand, Spacer(1, 0.3*inch),
            Paragraph('Relatório de Segurança', self.styles['CustomTitle']),
            Paragraph('Análise técnica de vulnerabilidades e plano de remediação',
                      self.styles['InfoText']),
            Spacer(1, 0.18*inch),
        ])

        metadata = [
            [self._cell('IDENTIFICAÇÃO', 'CardLabel'), self._cell('TIPO DE ANÁLISE', 'CardLabel')],
            [self._cell(f'Scan {scan_id}', 'CardValue'), self._cell(scan_type, 'CardValue')],
            [self._cell('ALVO', 'CardLabel'), self._cell('EMITIDO EM', 'CardLabel')],
            [self._cell(target, 'CardValue'),
             self._cell(datetime.now().strftime('%d/%m/%Y às %H:%M'), 'CardValue')],
        ]
        meta_table = Table(metadata, colWidths=[2.85*inch, 2.85*inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.SURFACE),
            ('BOX', (0, 0), (-1, -1), 0.6, self.BORDER),
            ('LINEBELOW', (0, 1), (-1, 1), 0.35, self.BORDER),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        elements.extend([meta_table, Spacer(1, 0.12*inch)])
        elements.append(Paragraph(
            'Classificação: uso interno. Os achados devem ser validados no contexto da aplicação antes de alterações em produção.',
            self.styles['SmallText']))
        
        return elements
    
    def _create_executive_summary(self, scan_data: Dict) -> List:
        """Cria sumário executivo"""
        elements = self._section_title(
            'Sumário executivo',
            'Visão objetiva da exposição identificada e da urgência de tratamento.'
        )
        
        summary = scan_data.get('summary', {})
        total = self._number(summary.get('total', 0))
        critical = self._number(summary.get('critical', 0))
        high = self._number(summary.get('high', 0))
        medium = self._number(summary.get('medium', 0))
        low = self._number(summary.get('low', 0))
        
        if critical > 0:
            risk_level = "CRÍTICO"
            risk_color = self.SEVERITY_COLORS['CRITICAL']
            action = 'Ação imediata: conter a exposição e iniciar a correção dos achados críticos.'
        elif high > 0:
            risk_level = "ALTO"
            risk_color = self.SEVERITY_COLORS['HIGH']
            action = 'Prioridade alta: planejar correções antes da próxima liberação para produção.'
        elif medium > 0:
            risk_level = "MÉDIO"
            risk_color = self.SEVERITY_COLORS['MEDIUM']
            action = 'Tratamento programado: reduzir a superfície de ataque no ciclo atual.'
        else:
            risk_level = "BAIXO"
            risk_color = self.SEVERITY_COLORS['LOW']
            action = 'Manter monitoramento e confirmar os controles de segurança existentes.'

        risk_card = Table([[
            Paragraph(f'<font size="8">RISCO GERAL</font><br/><font size="18"><b>{risk_level}</b></font>',
                      ParagraphStyle('RiskCard', parent=self.styles['Normal'], textColor=self.WHITE,
                                     leading=21)),
            Paragraph(
                f'Foram identificados <b>{total}</b> achado(s), sendo <b>{critical + high}</b> de alta prioridade.<br/>{self._safe(action)}',
                self.styles['InfoText'])
        ]], colWidths=[1.55*inch, 4.15*inch])
        risk_card.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), risk_color),
            ('BACKGROUND', (1, 0), (1, 0), self.SURFACE),
            ('BOX', (0, 0), (-1, -1), 0.6, self.BORDER),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        elements.extend([risk_card, Spacer(1, 0.14*inch)])

        data = [
            ['SEVERIDADE', 'QUANTIDADE', 'DISTRIBUIÇÃO'],
            [self._cell('Crítica'), self._cell(critical), self._cell(f'{(critical/total*100) if total > 0 else 0:.1f}%')],
            [self._cell('Alta'), self._cell(high), self._cell(f'{(high/total*100) if total > 0 else 0:.1f}%')],
            [self._cell('Média'), self._cell(medium), self._cell(f'{(medium/total*100) if total > 0 else 0:.1f}%')],
            [self._cell('Baixa'), self._cell(low), self._cell(f'{(low/total*100) if total > 0 else 0:.1f}%')],
        ]
        elements.append(self._standard_table(data, [2.5*inch, 1.4*inch, 1.8*inch]))
        return elements
    
    def _create_statistics_section(self, scan_data: Dict) -> List:
        """Cria seção de estatísticas com gráficos"""
        elements = self._section_title('Distribuição por severidade')
        
        summary = scan_data.get('summary', {})
        
        # Gráfico de pizza (com proteção para total = 0)
        data_values = [
            self._number(summary.get('critical', 0)),
            self._number(summary.get('high', 0)),
            self._number(summary.get('medium', 0)),
            self._number(summary.get('low', 0))
        ]
        total_values = sum(data_values)
        if total_values > 0:
            drawing = Drawing(410, 155)
            pie = Pie()
            pie.x = 55
            pie.y = 20
            pie.width = 115
            pie.height = 115
            pie.data = data_values
            pie.labels = [f'Crítica: {data_values[0]}', f'Alta: {data_values[1]}',
                          f'Média: {data_values[2]}', f'Baixa: {data_values[3]}']
            pie.slices.strokeWidth = 0.5
            pie.slices[0].fillColor = self.SEVERITY_COLORS['CRITICAL']
            pie.slices[1].fillColor = self.SEVERITY_COLORS['HIGH']
            pie.slices[2].fillColor = self.SEVERITY_COLORS['MEDIUM']
            pie.slices[3].fillColor = self.SEVERITY_COLORS['LOW']
            drawing.add(pie)
            elements.append(drawing)
        else:
            elements.append(Paragraph("Sem dados estatísticos disponíveis", self.styles['InfoText']))
        
        return elements

    def _create_prioritization_section(self, scan_data: Dict) -> List:
        vulnerabilities = self._findings(scan_data.get('vulnerabilities'))
        if not vulnerabilities:
            return []
        ordered = sorted(
            vulnerabilities,
            key=lambda item: ({'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(
                self._severity(item.get('severity')), 0), self._number(item.get('cvss'))),
            reverse=True,
        )
        elements = self._section_title(
            'Plano de priorização',
            'Ordem recomendada para triagem e remediação. A prioridade final deve considerar exposição e contexto de negócio.'
        )
        data = [['PRIORIDADE', 'ACHADO', 'REFERÊNCIA', 'AÇÃO RECOMENDADA']]
        for index, vuln in enumerate(ordered[:10], 1):
            references = self._finding_references(vuln)
            data.append([
                self._cell(f'P{index} · {self._severity(vuln.get("severity"))}'),
                self._cell(vuln.get('type') or vuln.get('title') or 'Achado de segurança'),
                self._cell(' · '.join(references) if references else 'Sem correlação'),
                self._cell(self._finding_recommendation(vuln)),
            ])
        elements.append(self._standard_table(
            data, [1.05*inch, 1.55*inch, 1.25*inch, 1.85*inch]
        ))
        return elements
    
    def _create_vulnerabilities_section(self, scan_data: Dict) -> List:
        """Cria seção detalhada de vulnerabilidades"""
        elements = self._section_title(
            'Detalhamento técnico dos achados',
            'Cada item apresenta classificação, possível correlação pública, evidência e orientação de correção.'
        )
        vulnerabilities = self._findings(scan_data.get('vulnerabilities'))
        if not vulnerabilities:
            elements.append(Paragraph(
                'Nenhum achado técnico detalhado foi disponibilizado para este relatório.',
                self.styles['InfoText']))
            return elements

        labels = {'CRITICAL': 'Críticos', 'HIGH': 'Altos', 'MEDIUM': 'Médios', 'LOW': 'Baixos'}
        for severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
            group = [v for v in vulnerabilities if self._severity(v.get('severity')) == severity]
            if not group:
                continue
            elements.append(Paragraph(
                f'{labels[severity]} ({len(group)})', self.styles['CustomSection']))
            for index, vuln in enumerate(group, 1):
                elements.extend(self._create_vulnerability_detail(vuln, severity, index))
        return elements

    def _finding_cves(self, vuln: Dict) -> List[str]:
        values = vuln.get('cves') or vuln.get('cve') or vuln.get('cve_id') or []
        if isinstance(values, str):
            values = [part.strip() for part in values.replace(';', ',').split(',')]
        elif isinstance(values, dict):
            values = list(values.keys())
        return [str(value).strip() for value in values if str(value).strip()]

    def _finding_references(self, vuln: Dict) -> List[str]:
        references = self._finding_cves(vuln)
        for key in ('cwe', 'owasp'):
            value = vuln.get(key)
            if value and str(value) not in references:
                references.append(str(value))
        if vuln.get('cvss') is not None:
            references.append(f"CVSS {vuln.get('cvss')}")
        return references

    def _finding_location(self, vuln: Dict) -> str:
        parts = []
        file_name = vuln.get('file') or vuln.get('filename') or vuln.get('path')
        line = vuln.get('line') or vuln.get('line_number')
        endpoint = vuln.get('endpoint') or vuln.get('url')
        if file_name:
            parts.append(str(file_name))
        if line:
            parts.append(f'linha {line}')
        if endpoint:
            parts.append(str(endpoint))
        if vuln.get('port'):
            parts.append(f"porta {vuln.get('port')}")
        return ' · '.join(parts) or 'Localização não informada pelo scanner'

    def _finding_recommendation(self, vuln: Dict) -> str:
        fix = vuln.get('fix')
        if isinstance(fix, dict):
            guidance = fix.get('guidance') or fix.get('recommendation')
            if guidance:
                return str(guidance)
        elif fix:
            return str(fix)
        return str(vuln.get('recommendation') or vuln.get('remediation') or
                   vuln.get('solution') or 'Revisar o fluxo afetado e aplicar controles compatíveis com o contexto.')

    def _finding_code_fix(self, vuln: Dict) -> str:
        fix = vuln.get('fix')
        if isinstance(fix, dict):
            for key in ('patch_template', 'code', 'example'):
                if fix.get(key):
                    return str(fix[key])
            commands = fix.get('terminal_commands')
            if isinstance(commands, dict) and commands:
                return '\n'.join(f'{platform}: {command}' for platform, command in commands.items())
        for key in ('suggested_code', 'code_fix', 'fix_suggestion', 'patch', 'safe_example'):
            if vuln.get(key):
                return str(vuln[key])

        finding_type = str(vuln.get('type') or vuln.get('title') or '').lower()
        suggestions = [
            (('sql injection',), "# Use consulta parametrizada; nunca concatene a entrada\ncursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"),
            (('command injection',), "# Passe argumentos como lista e mantenha shell desativado\nsubprocess.run(['tool', validated_value], check=True, shell=False)"),
            (('cross-site', 'xss'), "// Renderize entrada como texto; sanitize apenas quando HTML for necessário\nelement.textContent = userSuppliedValue;"),
            (('path traversal',), "# Resolva o caminho e confirme que ele permanece no diretório permitido\npath = (BASE_DIR / filename).resolve()"),
            (('hardcoded', 'secret', 'credential'), "# Carregue credenciais de um cofre ou variável de ambiente\napi_key = os.environ['API_KEY']"),
            (('rate limit',), "# Exemplo conceitual: limite por identidade e janela de tempo\nrate_limit(key=user_id, limit=100, window_seconds=60)"),
            (('cors',), "# Permita somente origens confiáveis\nallowed_origins = ['https://app.exemplo.com']"),
            (('header',), "# Configure o cabeçalho na camada web apropriada\nresponse.headers['X-Content-Type-Options'] = 'nosniff'"),
        ]
        for terms, suggestion in suggestions:
            if any(term in finding_type for term in terms):
                return suggestion
        return ''

    def _create_vulnerability_detail(self, vuln: Dict, severity: str, index: int) -> List:
        """Cria um cartão técnico completo para uma vulnerabilidade."""
        color = self.SEVERITY_COLORS[severity]
        title = vuln.get('type') or vuln.get('title') or 'Achado de segurança'
        identifier = vuln.get('id') or f'{severity[:1]}-{index:03d}'
        cves = self._finding_cves(vuln)
        references = self._finding_references(vuln)

        header = Table([[
            Paragraph(f'<b>{self._safe(title)}</b><br/><font size="7">ID {self._safe(identifier)}</font>',
                      ParagraphStyle('FindingTitle', parent=self.styles['InfoText'],
                                     textColor=self.WHITE, leading=13)),
            Paragraph(f'<b>{severity}</b>', ParagraphStyle(
                'SeverityBadge', parent=self.styles['InfoText'], textColor=self.WHITE,
                alignment=TA_RIGHT, fontSize=9))
        ]], colWidths=[4.7*inch, 1.0*inch])
        header.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), color),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 9),
            ('RIGHTPADDING', (0, 0), (-1, -1), 9),
            ('TOPPADDING', (0, 0), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ]))

        cve_text = ', '.join(cves) if cves else 'Não identificada pelo scanner; não inferida sem evidência.'
        reference_text = ' · '.join(references) if references else 'Sem CWE/OWASP/CVSS informado'
        meta = Table([
            [self._cell('LOCALIZAÇÃO', 'CardLabel'), self._cell('POSSÍVEL CVE', 'CardLabel')],
            [self._cell(self._finding_location(vuln), 'SmallText'), self._cell(cve_text, 'SmallText')],
            [self._cell('CLASSIFICAÇÕES', 'CardLabel'), self._cell('ORIGEM / CAMADA', 'CardLabel')],
            [self._cell(reference_text, 'SmallText'),
             self._cell(vuln.get('scanner') or vuln.get('layer') or vuln.get('service') or 'Scanner de segurança', 'SmallText')],
        ], colWidths=[2.85*inch, 2.85*inch])
        meta.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.SURFACE),
            ('BOX', (0, 0), (-1, -1), 0.5, self.BORDER),
            ('INNERGRID', (0, 0), (-1, -1), 0.3, self.BORDER),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))

        elements = [header, meta, Spacer(1, 0.08*inch)]
        description = vuln.get('description') or 'Descrição técnica não informada pelo scanner.'
        elements.append(Paragraph(
            f'<b>O que foi identificado</b><br/>{self._safe(description)}', self.styles['InfoText']))

        evidence = vuln.get('evidence') or vuln.get('code') or vuln.get('code_snippet') or vuln.get('request')
        if evidence:
            elements.append(Paragraph('<b>Evidência observada</b>', self.styles['InfoText']))
            elements.append(XPreformatted(self._safe(evidence), self.styles['MonospaceBlock']))

        elements.append(Paragraph(
            f'<b>O que corrigir</b><br/>{self._safe(self._finding_recommendation(vuln))}',
            self.styles['InfoText']))

        code_fix = self._finding_code_fix(vuln)
        if code_fix:
            elements.append(Paragraph(
                '<b>Sugestão de ajuste no código/configuração</b>', self.styles['InfoText']))
            elements.append(XPreformatted(self._safe(code_fix), self.styles['MonospaceBlock']))
        else:
            elements.append(Paragraph(
                '<b>Sugestão de implementação</b><br/>Não há patch seguro e universal para este achado. '
                'Aplique a recomendação no framework utilizado, acrescente teste de regressão e submeta a alteração à revisão técnica.',
                self.styles['InfoText']))

        validation = vuln.get('validation') or vuln.get('review_required')
        if isinstance(vuln.get('fix'), dict):
            validation = validation or vuln['fix'].get('review_required')
        validation = validation or 'Reproduzir o cenário após a correção, executar testes automatizados e confirmar que o controle não introduziu regressões.'
        elements.extend([
            Paragraph(f'<b>Como validar a correção</b><br/>{self._safe(validation)}', self.styles['InfoText']),
            Spacer(1, 0.14*inch),
        ])
        return elements
    
    def _create_recommendations_section(self, scan_data: Dict) -> List:
        """Cria seção de recomendações"""
        elements = self._section_title(
            'Plano de ação recomendado',
            'Etapas de governança para transformar os achados em correções verificáveis.'
        )
        actions = [
            ('IMEDIATO', 'Conter e confirmar', 'Validar achados críticos/altos, reduzir exposição e definir responsáveis.'),
            ('CURTO PRAZO', 'Corrigir e testar', 'Aplicar as remediações, incluir testes de regressão e realizar revisão de código.'),
            ('ANTES DO DEPLOY', 'Revalidar', 'Executar novo scan, confirmar o fechamento dos achados e registrar evidências.'),
            ('CONTÍNUO', 'Prevenir recorrência', 'Integrar análise no CI/CD, atualizar dependências e acompanhar métricas de segurança.'),
        ]
        data = [['PRAZO', 'ETAPA', 'CRITÉRIO DE CONCLUSÃO']]
        for deadline, stage, criterion in actions:
            data.append([self._cell(deadline, 'SmallText'), self._cell(stage), self._cell(criterion)])
        elements.append(self._standard_table(data, [1.15*inch, 1.45*inch, 3.1*inch]))
        return elements

    def _create_tools_responses_section(self, scans: List[Dict[str, Any]]) -> List:
        elements = self._section_title(
            'Apêndice técnico — evidências brutas',
            'Extratos preservados para rastreabilidade. O conteúdo pode estar truncado para manter a legibilidade.'
        )

        groups: Dict[str, List[Dict[str, Any]]] = {}
        for s in scans:
            t = s.get('tool', str(s.get('scan_type', '')).upper())
            groups.setdefault(t, []).append(s)

        for tool, items in groups.items():
            banner = Table([[self._cell(tool, 'CardValue')]], colWidths=[5.7*inch])
            banner.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#E2E8F0')),
                ('LINEBEFORE', (0, 0), (0, -1), 4, self.BLUE),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 7),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
            ]))
            elements.append(banner)
            elements.append(Spacer(1, 0.08 * inch))

            total_scans = len(items)
            total_vulns = sum(int(i.get('total_vulnerabilities', 0)) for i in items)
            elements.append(Paragraph(
                f'<b>{total_scans}</b> scan(s) · <b>{total_vulns}</b> achado(s)',
                self.styles['SmallText']))
            elements.append(Spacer(1, 0.12 * inch))

            for s in items:
                sc = s.get('severity_count', {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0})
                meta_table = Table(
                    [
                        [self._cell(f"Scan {s.get('id', '')}", 'CardValue'),
                         self._cell(self._format_date(s.get('created_at')), 'SmallText')],
                        [self._cell(f"Alvo: {s.get('target', '')}", 'SmallText'), ""],
                    ],
                    colWidths=[3.5*inch, 2.2*inch]
                )
                meta_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), self.SURFACE),
                    ('BOX', (0, 0), (-1, -1), 0.5, self.BORDER),
                    ('SPAN', (0, 1), (1, 1)),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ]))
                elements.append(meta_table)
                elements.append(Spacer(1, 0.06 * inch))

                severity_table = Table(
                    [[self._cell('CRÍTICAS', 'CardLabel'), self._cell('ALTAS', 'CardLabel'),
                      self._cell('MÉDIAS', 'CardLabel'), self._cell('BAIXAS', 'CardLabel')],
                     [self._cell(sc.get('CRITICAL', 0)), self._cell(sc.get('HIGH', 0)),
                      self._cell(sc.get('MEDIUM', 0)), self._cell(sc.get('LOW', 0))]],
                    colWidths=[1.2*inch, 1.2*inch, 1.2*inch, 1.2*inch]
                )
                severity_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), self.WHITE),
                    ('GRID', (0, 0), (-1, -1), 0.35, self.BORDER),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ]))
                elements.append(severity_table)
                elements.append(Spacer(1, 0.06 * inch))

                raw = s.get('raw_excerpt', '')
                if raw:
                    # XPreformatted também interpreta tags do ReportLab. Resultados
                    # de scans podem conter HTML capturado e devem ser texto literal.
                    text_str = escape(str(raw))
                    elements.append(XPreformatted(text_str, self.styles['MonospaceBlock']))
                    elements.append(Spacer(1, 0.06 * inch))
                elements.append(Spacer(1, 0.12 * inch))

        return elements
    
    def _create_footer(self) -> List:
        """Cria rodapé do relatório"""
        return [Spacer(1, 0.3*inch), self._create_line(), Paragraph(
            f'Relatório gerado automaticamente pela plataforma Iron Net · {datetime.now().year}<br/>'
            '<b>CONFIDENCIAL — Uso interno. Validar os achados antes de alterações em produção.</b>',
            ParagraphStyle('DocumentFooter', parent=self.styles['SmallText'], alignment=TA_CENTER))]
    
    def _create_line(self):
        """Cria linha separadora"""
        from reportlab.platypus import HRFlowable
        return HRFlowable(
            width="100%",
            thickness=1,
            lineCap='round',
            color=self.BORDER,
            spaceBefore=6,
            spaceAfter=6
        )
    
    def _add_page_number(self, canvas, doc):
        """Adiciona número de página"""
        page_num = canvas.getPageNumber()
        width, height = doc.pagesize
        canvas.saveState()
        canvas.setStrokeColor(self.BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(42, 35, width - 42, 35)
        canvas.setFont('Helvetica', 7.5)
        canvas.setFillColor(self.MUTED)
        canvas.drawString(42, 23, 'IRON NET · RELATÓRIO DE SEGURANÇA · CONFIDENCIAL')
        canvas.drawRightString(width - 42, 23, f'Página {page_num}')
        if page_num > 1:
            canvas.setFont('Helvetica-Bold', 7.5)
            canvas.setFillColor(self.NAVY)
            canvas.drawString(42, height - 30, 'IRON NET / SECURITY')
        canvas.restoreState()


def generate_pdf_report(scan_data: Dict[str, Any], output_path: str = None) -> bytes:
    """Gera o relatório e mantém uma saída válida mesmo com dados inesperados."""
    try:
        generator = PDFReportGenerator()
        return generator.generate_scan_report(scan_data if isinstance(scan_data, dict) else {}, output_path)
    except Exception:
        # O relatório não deve deixar de ser emitido por causa de um campo atípico
        # retornado por algum scanner. A contingência preserva os dados essenciais.
        buffer = output_path or io.BytesIO()
        safe_data = scan_data if isinstance(scan_data, dict) else {}
        doc = SimpleDocTemplate(
            buffer, pagesize=A4, rightMargin=48, leftMargin=48,
            topMargin=54, bottomMargin=46,
            title='Relatório de Segurança', author='Iron Net',
        )
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'FallbackTitle', parent=styles['Title'], fontName='Helvetica-Bold',
            fontSize=22, leading=27, textColor=PDFReportGenerator.NAVY,
            alignment=TA_LEFT, spaceAfter=18,
        )
        body_style = ParagraphStyle(
            'FallbackBody', parent=styles['BodyText'], fontSize=9, leading=13,
            textColor=PDFReportGenerator.SLATE, spaceAfter=8,
        )
        safe = lambda value: escape(str(value if value not in (None, '') else 'Não informado'))
        summary = safe_data.get('summary') if isinstance(safe_data.get('summary'), dict) else {}
        story = [
            Paragraph('IRON NET / SECURITY', styles['Heading3']),
            Paragraph('Relatório de Segurança', title_style),
            Paragraph(f"<b>Scan:</b> {safe(safe_data.get('scan_id'))}", body_style),
            Paragraph(f"<b>Tipo:</b> {safe(safe_data.get('scan_type'))}", body_style),
            Paragraph(f"<b>Alvo:</b> {safe(safe_data.get('target'))}", body_style),
            Spacer(1, 12),
            Paragraph('Resumo da análise', styles['Heading2']),
            Paragraph(
                f"Total: <b>{safe(summary.get('total', 0))}</b> · "
                f"Críticas: <b>{safe(summary.get('critical', 0))}</b> · "
                f"Altas: <b>{safe(summary.get('high', 0))}</b> · "
                f"Médias: <b>{safe(summary.get('medium', 0))}</b> · "
                f"Baixas: <b>{safe(summary.get('low', 0))}</b>", body_style),
            Spacer(1, 12),
            Paragraph(
                'O relatório foi emitido em modo de compatibilidade porque o resultado contém '
                'um formato não padronizado. Os dados essenciais foram preservados.', body_style),
        ]
        doc.build(story)
        return buffer.getvalue() if isinstance(buffer, io.BytesIO) else None
