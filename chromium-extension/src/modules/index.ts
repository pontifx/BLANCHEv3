import type { ModuleDefinition } from '../shared/contracts';
import { burpBridgeModule } from './burpBridge';
import { documentAcquisitionModule } from './documentAcquisition';
import { osintSeedModule } from './osintSeed';
import { latentFeaturesModule } from './latentFeatures';

export const registeredModules: ModuleDefinition[] = [
  burpBridgeModule,
  osintSeedModule,
  documentAcquisitionModule,
  latentFeaturesModule
];
