import reprlib

from celery import task
from celery.utils.log import get_task_logger

from core.models import Job
from core.notifications import send_notification
from .models import CriticalStack

logger = get_task_logger(__name__)

repr_instance = reprlib.Repr()
repr_instance.maxstring = 200


@task
def deploy_critical_stack(api_key):
    job = Job.create_job('deploy_critical_stack', api_key)
    try:
        critical_stack = CriticalStack.objects.get(api_key=api_key)
    except CriticalStack.DoesNotExist:  # pragma: no cover
        logger.exception()
        job.update_job("Error - Critical Stack is None - param id not set : " + str(api_key), 'Error')
        return {"message": "Error - Critical Stack is None - param id not set : " + str(api_key)}
    else:
        try:
            response_deploy_critical_stack = critical_stack.deploy()
            if response_deploy_critical_stack['status']:
                job.update_job('Deployed Critical Stack successfully', 'Completed')
            elif not response_deploy_critical_stack['status']:  # pragma: no cover
                if 'errors' in response_deploy_critical_stack:
                    job.update_job('Error during the critical stack deployed',
                                   'Error: ' + str(api_key) + " - " +
                                   repr_instance.repr(response_deploy_critical_stack['errors']))
                    logger.error("task - deploy_critical_stack : " + str(api_key) + " - " +
                                 repr_instance.repr(response_deploy_critical_stack['errors']))
                    return {"message": "Error for Critical Stack " + str(api_key) + " to deploy",
                            "exception": str(response_deploy_critical_stack['errors'])}
                else:
                    job.update_job('Error during the critical stack deployed', 'Error: ' + str(api_key))
                    logger.error("task - deploy_critical_stack : " + str(api_key))
                    return {"message": "Error for Critical Stack " + str(api_key) + " to deploy", "exception": " "}
        except Exception as e:  # pragma: no cover
            logger.exception('Error during the critical stack deployed')
            job.update_job(repr_instance.repr(e), 'Error')
            send_notification("Critical stack " + str(api_key), str(e))
            return {"message": "Error for Critical Stack " + str(api_key) + " to deploy", "exception": str(e)}
        return {"message": "Critical Stack " + str(api_key) + ' deployed successfully'}
