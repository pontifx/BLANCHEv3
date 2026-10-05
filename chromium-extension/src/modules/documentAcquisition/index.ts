import type { ModuleDefinition, ModuleDescriptor } from '../../shared/contracts';
import descriptorJson from './descriptor.json';
import { createDocumentAcquisitionBackgroundController } from './background';

const descriptor = descriptorJson as ModuleDescriptor;

export const documentAcquisitionModule: ModuleDefinition = {
  descriptor,
  createBackgroundController({ logger, host }) {
    return createDocumentAcquisitionBackgroundController({
      descriptor,
      logger,
      host
    });
  }
};
