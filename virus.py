import pendulum
from virustotals.config import *
from virustotals.totals import Virus
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.operators.bash import BashOperator
from datetime import date,timedelta ,datetime 
import os
import logging
import pandas as pd

def read_data(filepath=None):
    logging.info(os.getcwd())
    df = pd.read_csv(f'dags/virustotals/{filepath}')
    df.to_csv('dags/virustotals/tmp.csv',index=False)
    return filepath

def _virus_detect(src,dest,df,mykey,**context):
    filepath = context['task_instance'].xcom_pull(task_ids='read_data')
    df = pd.read_csv('dags/virustotals/tmp.csv')
    result = Virus(src=src,dest=dest,df=df,mykey=mykey).detect()
    result.to_csv(f'dags/virustotals/detect{filepath}',index=False)
with DAG(
    dag_id = 'virus',
    start_date=datetime.now(),
    schedule_interval="@hourly",
) as dag:
    read_data = PythonOperator(task_id = 'read_data' , 
                                python_callable =read_data,
                                op_kwargs={'filepath':'2023-04-16.csv'},
                                dag=dag
                            )
    defines =PythonOperator(task_id ='define_instance',
                             python_callable = _virus_detect,
                             op_kwargs={
                                 'src' : 'src_ip',
                                 'dest' : 'dest_ip',
                                 'mykey' : apikey2,
                                 'df' : None,
                                 },
                            dag=dag
                             )
    delete = BashOperator(
            task_id = 'delete_tmp_csv',
            bash_command='rm -rf dags/virustotals/tmp.csv',
            dag = dag
            ) 
    read_data >> defines >> delete
