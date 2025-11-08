import Router from 'express';
import authRoutes from './authRoute.js';
// import projectRoutes from './routes/projects.js';
// import taskRoutes from './routes/projects.js';
// import teamRoutes from '../routes/team.js';

const router = Router();

router.use('/api', authRoutes);
// router.use('/api', projectRoutes);
// router.use('/api', taskRoutes);
// router.use('/api', teamRoutes);

export default router;

