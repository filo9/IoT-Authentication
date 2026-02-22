import { createApp } from 'vue'
import AppPQC from './AppPQC.vue'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import 'element-plus/theme-chalk/dark/css-vars.css'

const app = createApp(AppPQC)
app.use(ElementPlus)
app.mount('#app')
