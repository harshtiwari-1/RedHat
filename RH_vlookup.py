import pandas as pd
import datetime

tday = datetime.date.today()
from pandas import DataFrame, read_excel, merge

excel_file = 'Redhat Updates.xlsx'
df2 = pd.read_excel(excel_file, sheet_name="Master CVE")
df1 = pd.read_excel(excel_file, sheet_name="Security Updates")
df3 = pd.read_excel(excel_file, sheet_name="Sheet1")

#mastercve_sheet2 = pd.read_excel(excel_file, sheet_name=1, index_col=0)

df4 = df1.merge(df2, on='Details', how='left')

# SAVE TO A .XLSX

with pd.ExcelWriter(f'redhat_{tday.strftime("%B")}-{tday.year}.xlsx') as writer:
    df4.to_excel(writer, sheet_name='Security Updates', index=False)
    df2.to_excel(writer, sheet_name='Master CVE', index=False)
    df3.to_excel(writer, sheet_name='Advisory Details', index=False)

print(f'redhat_{tday.strftime("%B")}-{tday.year}.xlsx saved' )
