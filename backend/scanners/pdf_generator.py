"""
Professional PDF Report Generator
Gera relatórios detalhados e profissionais em PDF
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, KeepTogether, Preformatted, XPreformatted
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from datetime import datetime
from typing import Dict, List, Any
import io


class PDFReportGenerator:
    """Gerador de relatórios PDF profissionais"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Configura estilos customizados"""
        
        # Título principal
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Subtítulo
        self.styles.add(ParagraphStyle(
            name='CustomSubtitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))
        
        # Seção
        self.styles.add(ParagraphStyle(
            name='CustomSection',
            parent=self.styles['Heading3'],
            fontSize=14,
            textColor=colors.HexColor('#34495e'),
            spaceAfter=10,
            spaceBefore=10,
            fontName='Helvetica-Bold'
        ))
        
        # Texto de alerta crítico
        self.styles.add(ParagraphStyle(
            name='CriticalAlert',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#c0392b'),
            spaceAfter=6,
            fontName='Helvetica-Bold'
        ))
        
        # Texto de alerta alto
        self.styles.add(ParagraphStyle(
            name='HighAlert',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#e67e22'),
            spaceAfter=6,
            fontName='Helvetica-Bold'
        ))
        
        # Informação
        self.styles.add(ParagraphStyle(
            name='InfoText',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#7f8c8d'),
            spaceAfter=6,
            alignment=TA_JUSTIFY
        ))
        # Bloco monoespaçado para respostas
        self.styles.add(ParagraphStyle(
            name='MonospaceBlock',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=6,
            fontName='Courier'
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
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        # Container para elementos
        story = []
        
        # Cabeçalho
        story.extend(self._create_header(scan_data))
        story.append(Spacer(1, 0.2 * inch))

        if scan_data.get('user_overview'):
            story.extend(self._create_user_overview(scan_data['user_overview']))
            story.append(Spacer(1, 0.15 * inch))
        if scan_data.get('tools_summary'):
            story.extend(self._create_tools_overview(scan_data['tools_summary']))
            story.append(Spacer(1, 0.15 * inch))
        if scan_data.get('scans_details'):
            story.extend(self._create_scan_list_section(scan_data['scans_details']))
            story.append(Spacer(1, 0.2 * inch))
        
        # Sumário Executivo
        story.extend(self._create_executive_summary(scan_data))
        
        # Gráficos e Estatísticas
        story.extend(self._create_statistics_section(scan_data))
        
        # Detalhes das Vulnerabilidades
        story.extend(self._create_vulnerabilities_section(scan_data))

        # Respostas das Ferramentas
        if scan_data.get('scans_details'):
            story.extend(self._create_tools_responses_section(scan_data['scans_details']))
        
        # Recomendações
        story.extend(self._create_recommendations_section(scan_data))
        
        # Rodapé
        story.extend(self._create_footer())
        
        # Construir PDF
        doc.build(story, onFirstPage=self._add_page_number, onLaterPages=self._add_page_number)
        
        # Retornar bytes se foi usado buffer
        if isinstance(buffer, io.BytesIO):
            return buffer.getvalue()
        
        return None

    def _create_user_overview(self, overview: Dict) -> List:
        elements = []
        elements.append(Paragraph("Visão Geral do Usuário", self.styles['CustomSubtitle']))
        total_scans = overview.get('total_scans', 0)
        total_vulns = overview.get('total_vulnerabilities', 0)
        sc = overview.get('severity_count', {'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0})
        data = [
            ['Total de Scans', str(total_scans)],
            ['Total de Vulnerabilidades', str(total_vulns)],
            ['Críticas', str(sc.get('CRITICAL', 0))],
            ['Altas', str(sc.get('HIGH', 0))],
            ['Médias', str(sc.get('MEDIUM', 0))],
            ['Baixas', str(sc.get('LOW', 0))]
        ]
        table = Table(data, colWidths=[3*inch, 2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ]))
        elements.append(table)
        return elements

    def _create_tools_overview(self, tools: List[Dict[str, Any]]) -> List:
        elements = []
        elements.append(Paragraph("Ferramentas Utilizadas", self.styles['CustomSubtitle']))
        data = [['Ferramenta', 'Scans', 'Vulnerabilidades']]
        for t in tools:
            data.append([t.get('tool', ''), str(t.get('scans', 0)), str(t.get('vulnerabilities', 0))])
        table = Table(data, colWidths=[3*inch, 1.25*inch, 1.75*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ]))
        elements.append(table)
        return elements

    def _create_scan_list_section(self, scans: List[Dict[str, Any]]) -> List:
        elements = []
        elements.append(Paragraph("Linha do Tempo dos Scans", self.styles['CustomSubtitle']))
        data = [['ID', 'Tipo', 'Target', 'Data', 'Vulnerabilidades']]
        for s in scans[:30]:
            data.append([
                str(s.get('id', '')),
                str(s.get('scan_type', '')).upper(),
                s.get('target', ''),
                s.get('created_at', ''),
                str(s.get('total_vulnerabilities', 0))
            ])
        table = Table(data, colWidths=[0.8*inch, 1.2*inch, 2.2*inch, 1.6*inch, 1.2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ]))
        elements.append(table)
        return elements
    
    def _create_header(self, scan_data: Dict) -> List:
        """Cria cabeçalho do relatório"""
        elements = []
        
        # Título
        title = Paragraph(
            "Security Scan Report",
            self.styles['CustomTitle']
        )
        elements.append(title)
        
        # Informações do scan
        scan_info = f"""
        <para alignment='center'>
        <font size=10 color='#7f8c8d'>
        <b>Scan ID:</b> {scan_data.get('scan_id', 'N/A')}<br/>
        <b>Data:</b> {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}<br/>
        <b>Tipo:</b> {scan_data.get('scan_type', 'Code Analysis').upper()}<br/>
        <b>Target:</b> {scan_data.get('target', 'N/A')}
        </font>
        </para>
        """
        elements.append(Paragraph(scan_info, self.styles['Normal']))
        elements.append(Spacer(1, 0.2 * inch))
        
        # Linha separadora
        elements.append(self._create_line())
        
        return elements
    
    def _create_executive_summary(self, scan_data: Dict) -> List:
        """Cria sumário executivo"""
        elements = []
        
        elements.append(Paragraph("Sumário Executivo", self.styles['CustomSubtitle']))
        
        summary = scan_data.get('summary', {})
        total = summary.get('total', 0)
        critical = summary.get('critical', 0)
        high = summary.get('high', 0)
        medium = summary.get('medium', 0)
        low = summary.get('low', 0)
        
        # Avaliação geral
        if critical > 0:
            risk_level = "CRÍTICO"
            risk_color = "#c0392b"
        elif high > 0:
            risk_level = "ALTO"
            risk_color = "#e67e22"
        elif medium > 0:
            risk_level = "MÉDIO"
            risk_color = "#f39c12"
        else:
            risk_level = "BAIXO"
            risk_color = "#27ae60"
        
        summary_text = f"""
        <para alignment='justify'>
        O scan de segurança identificou <b>{total}</b> potenciais vulnerabilidades no código analisado.
        O nível de risco geral é classificado como <font color='{risk_color}'><b>{risk_level}</b></font>.
        </para>
        """
        elements.append(Paragraph(summary_text, self.styles['InfoText']))
        elements.append(Spacer(1, 0.2 * inch))
        
        # Tabela de resumo
        data = [
            ['Severidade', 'Quantidade', 'Percentual'],
            ['Crítica', str(critical), f'{(critical/total*100) if total > 0 else 0:.1f}%'],
            ['Alta', str(high), f'{(high/total*100) if total > 0 else 0:.1f}%'],
            ['Média', str(medium), f'{(medium/total*100) if total > 0 else 0:.1f}%'],
            ['Baixa', str(low), f'{(low/total*100) if total > 0 else 0:.1f}%'],
            ['', f'Total: {total}', '100%']
        ]
        
        table = Table(data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -2), colors.beige),
            ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#ecf0f1')),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ]))
        
        elements.append(table)
        
        return elements
    
    def _create_statistics_section(self, scan_data: Dict) -> List:
        """Cria seção de estatísticas com gráficos"""
        elements = []
        
        elements.append(Paragraph("Análise Estatística", self.styles['CustomSubtitle']))
        elements.append(Spacer(1, 0.2 * inch))
        
        summary = scan_data.get('summary', {})
        
        # Gráfico de pizza (com proteção para total = 0)
        data_values = [
            summary.get('critical', 0),
            summary.get('high', 0),
            summary.get('medium', 0),
            summary.get('low', 0)
        ]
        total_values = sum(data_values)
        if total_values > 0:
            drawing = Drawing(400, 200)
            pie = Pie()
            pie.x = 150
            pie.y = 50
            pie.width = 100
            pie.height = 100
            pie.data = data_values
            pie.labels = ['Crítica', 'Alta', 'Média', 'Baixa']
            pie.slices.strokeWidth = 0.5
            pie.slices[0].fillColor = colors.HexColor('#c0392b')
            pie.slices[1].fillColor = colors.HexColor('#e67e22')
            pie.slices[2].fillColor = colors.HexColor('#f39c12')
            pie.slices[3].fillColor = colors.HexColor('#27ae60')
            drawing.add(pie)
            elements.append(drawing)
        else:
            elements.append(Paragraph("Sem dados estatísticos disponíveis", self.styles['InfoText']))
        
        return elements
    
    def _create_vulnerabilities_section(self, scan_data: Dict) -> List:
        """Cria seção detalhada de vulnerabilidades"""
        elements = []
        
        elements.append(Paragraph("Detalhes das Vulnerabilidades", self.styles['CustomSubtitle']))
        elements.append(Spacer(1, 0.2 * inch))
        
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        # Agrupar por severidade
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'CRITICAL']
        high_vulns = [v for v in vulnerabilities if v.get('severity') == 'HIGH']
        medium_vulns = [v for v in vulnerabilities if v.get('severity') == 'MEDIUM']
        low_vulns = [v for v in vulnerabilities if v.get('severity') == 'LOW']
        
        # Vulnerabilidades críticas
        if critical_vulns:
            elements.append(Paragraph("Vulnerabilidades Críticas", self.styles['CustomSection']))
            for vuln in critical_vulns[:10]:  # Limitar a 10
                elements.extend(self._create_vulnerability_detail(vuln, 'CRITICAL'))
        
        # Vulnerabilidades altas
        if high_vulns:
            elements.append(Paragraph("Vulnerabilidades Altas", self.styles['CustomSection']))
            for vuln in high_vulns[:10]:
                elements.extend(self._create_vulnerability_detail(vuln, 'HIGH'))
        
        # Vulnerabilidades médias (resumo)
        if medium_vulns:
            elements.append(Paragraph(f"Vulnerabilidades Médias ({len(medium_vulns)})", self.styles['CustomSection']))
            elements.append(Paragraph(
                f"Foram encontradas {len(medium_vulns)} vulnerabilidades de severidade média. Recomenda-se revisar e corrigir.",
                self.styles['InfoText']
            ))
        
        # Vulnerabilidades baixas (resumo)
        if low_vulns:
            elements.append(Paragraph(f"Vulnerabilidades Baixas ({len(low_vulns)})", self.styles['CustomSection']))
            elements.append(Paragraph(
                f"Foram encontradas {len(low_vulns)} vulnerabilidades de severidade baixa.",
                self.styles['InfoText']
            ))
        
        return elements
    
    def _create_vulnerability_detail(self, vuln: Dict, severity: str) -> List:
        """Cria detalhes de uma vulnerabilidade"""
        elements = []
        
        # Tipo de vulnerabilidade
        vuln_type = vuln.get('type', 'Unknown')
        elements.append(Paragraph(f"<b>{vuln_type}</b>", self.styles['CriticalAlert' if severity == 'CRITICAL' else 'HighAlert']))
        
        # Localização
        location = vuln.get('line', vuln.get('endpoint', 'Unknown'))
        elements.append(Paragraph(f"<i>Localização: {location}</i>", self.styles['InfoText']))
        
        # Descrição
        description = vuln.get('description', 'Sem descrição')
        elements.append(Paragraph(f"{description}", self.styles['InfoText']))
        
        # Recomendação
        recommendation = vuln.get('recommendation', 'Revise o código')
        elements.append(Paragraph(f"<b>Recomendação:</b> {recommendation}", self.styles['InfoText']))
        
        elements.append(Spacer(1, 0.15 * inch))
        
        return elements
    
    def _create_recommendations_section(self, scan_data: Dict) -> List:
        """Cria seção de recomendações"""
        elements = []
        
        elements.append(Paragraph("Recomendações Gerais", self.styles['CustomSubtitle']))
        elements.append(Spacer(1, 0.1 * inch))
        
        recommendations = [
            "Priorize a correção de vulnerabilidades críticas e altas imediatamente",
            "Implemente code review obrigatório antes de merge para produção",
            "Configure ferramentas de análise estática no CI/CD pipeline",
            "Mantenha todas as dependências atualizadas regularmente",
            "Realize testes de segurança periódicos (mensal ou trimestral)",
            "Implemente logging e monitoring de eventos de segurança",
            "Ofereça treinamento de secure coding para a equipe",
            "Estabeleça um processo de resposta a incidentes de segurança"
        ]
        
        for i, rec in enumerate(recommendations, 1):
            elements.append(Paragraph(f"{i}. {rec}", self.styles['InfoText']))
        
        return elements

    def _create_tools_responses_section(self, scans: List[Dict[str, Any]]) -> List:
        elements = []
        elements.append(Paragraph("Respostas das Ferramentas", self.styles['CustomSubtitle']))
        elements.append(Spacer(1, 0.1 * inch))

        groups: Dict[str, List[Dict[str, Any]]] = {}
        for s in scans:
            t = s.get('tool', str(s.get('scan_type', '')).upper())
            groups.setdefault(t, []).append(s)

        for tool, items in groups.items():
            banner = Table([[tool]], colWidths=[6*inch])
            banner.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#7c3aed')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 12),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            elements.append(banner)
            elements.append(Spacer(1, 0.08 * inch))

            total_scans = len(items)
            total_vulns = sum(int(i.get('total_vulnerabilities', 0)) for i in items)
            summary_table = Table(
                [["Scans", str(total_scans)], ["Vulnerabilidades", str(total_vulns)]],
                colWidths=[2.5*inch, 3.5*inch]
            )
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#ecf0f1')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2c3e50')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#bdc3c7')),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(summary_table)
            elements.append(Spacer(1, 0.12 * inch))

            for s in items:
                sc = s.get('severity_count', {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0})
                meta_table = Table(
                    [
                        [f"Scan {s.get('id', '')}", s.get('created_at', '')],
                        [f"Target: {s.get('target', '')}", ""],
                    ],
                    colWidths=[3.2*inch, 2.8*inch]
                )
                meta_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f7f9fc')),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2c3e50')),
                    ('ALIGN', (0, 0), (0, 0), 'LEFT'),
                    ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#bdc3c7')),
                    ('SPAN', (0, 1), (1, 1)),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ]))
                elements.append(meta_table)
                elements.append(Spacer(1, 0.06 * inch))

                severity_table = Table(
                    [
                        ["Críticas", str(sc.get('CRITICAL', 0))],
                        ["Altas", str(sc.get('HIGH', 0))],
                        ["Médias", str(sc.get('MEDIUM', 0))],
                        ["Baixas", str(sc.get('LOW', 0))],
                    ],
                    colWidths=[2.2*inch, 1.0*inch]
                )
                severity_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#ecf0f1')),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2c3e50')),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#bdc3c7')),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ]))
                elements.append(severity_table)
                elements.append(Spacer(1, 0.06 * inch))

                raw = s.get('raw_excerpt', '')
                if raw:
                    text_str = str(raw)
                    elements.append(XPreformatted(text_str, self.styles['MonospaceBlock']))
                    elements.append(Spacer(1, 0.06 * inch))
                elements.append(Spacer(1, 0.12 * inch))

        return elements
    
    def _create_footer(self) -> List:
        """Cria rodapé do relatório"""
        elements = []
        
        elements.append(Spacer(1, 0.5 * inch))
        elements.append(self._create_line())
        
        footer_text = """
        <para alignment='center'>
        <font size=8 color='#95a5a6'>
        Este relatório foi gerado automaticamente pela plataforma Iron Net<br/>
        © 2025 Iron Net - Professional Security Analysis Tool<br/>
        <b>⚠️ CONFIDENCIAL - Para uso interno apenas</b>
        </font>
        </para>
        """
        elements.append(Paragraph(footer_text, self.styles['Normal']))
        
        return elements
    
    def _create_line(self):
        """Cria linha separadora"""
        from reportlab.platypus import HRFlowable
        return HRFlowable(
            width="100%",
            thickness=1,
            lineCap='round',
            color=colors.HexColor('#bdc3c7'),
            spaceBefore=6,
            spaceAfter=6
        )
    
    def _add_page_number(self, canvas, doc):
        """Adiciona número de página"""
        page_num = canvas.getPageNumber()
        text = f"Página {page_num}"
        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(colors.HexColor('#7f8c8d'))
        canvas.drawRightString(
            doc.pagesize[0] - 72,
            30,
            text
        )


def generate_pdf_report(scan_data: Dict[str, Any], output_path: str = None) -> bytes:
    """Função helper para gerar relatório PDF"""
    generator = PDFReportGenerator()
    return generator.generate_scan_report(scan_data, output_path)
