import type { ModuleDefinition, ModuleDescriptor } from '../../shared/contracts';
import descriptorJson from './descriptor.json';
import { createLatentFeaturesBackgroundController } from './background';

const descriptor = descriptorJson as ModuleDescriptor;

export const latentFeaturesModule: ModuleDefinition = {
  descriptor,
  createBackgroundController({ logger, host }) {
    return createLatentFeaturesBackgroundController({
      descriptor,
      logger,
      host
    });
  }
};
