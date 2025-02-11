import { LoadingOutlined } from '@ant-design/icons';
import type { FormInstance } from 'antd/lib/form';
import React from 'react';
import { formatMessage } from 'umi';

import { request as appRequest } from '@/app';
import type { UserModule } from '@/pages/User/typing';

const formRef = React.createRef<FormInstance>();

const LoginMethodOIDC: UserModule.LoginMethod = {
  id: 'OIDC',
  name: formatMessage({ id: 'component.user.loginMethodODIC' }),
  render: () => {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: '45px 0 100px 0 ' }}>
        <LoadingOutlined style={{ fontSize: '40px' }} />
      </div>
    );
  },
  redirectTo: `${appRequest.prefix}/oidc/login`,
  getData(): UserModule.LoginData {
    if (formRef.current) {
      const data = formRef.current.getFieldsValue();
      return {
        username: data.username,
        password: data.password,
      };
    }
    return {};
  },
  checkData: async () => {
    if (formRef.current) {
      try {
        await formRef.current.validateFields();
        return true;
      } catch (e) {
        return false;
      }
    }
    return false;
  },
  submit: async () => {
    return { status: false, message: '', data: {} };
  },
  logout: () => {
    localStorage.removeItem('token');
  },
};

export default LoginMethodOIDC;
